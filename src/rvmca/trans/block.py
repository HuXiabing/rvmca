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
from typing import List

from rvmca.config import *
from rvmca.prog import Program, IType, XREG
from rvmca.utils.cmd_util import run_cmd
from rvmca.utils.file_util import write_to_file
import random
import string
import re


def check_block_validity(prog: Program):
    """Check the validity of a block"""
    for inst in prog.insts[0:-1]:
        assert inst.type not in [IType.Branch, IType.Jump], f"{prog.insts} is not a basic block"
    for inst in prog.insts:
        addr = inst.get_addr()
        if addr:
            assert addr is not XREG[0], f"{inst} has zero address"


def __generate_random_string(length=6):
    characters = string.ascii_letters + string.digits
    random_string = ''.join(random.choice(characters) for i in range(length))
    return random_string


def __assemble(insts: List[str]) -> str:
    """assemble insts to codes"""
    code = '\n'.join(insts)
    tmp_filename = f'{OUTPUT_PATH / __generate_random_string()}'
    write_to_file(f'{tmp_filename}.S', code, append=False)
    run_cmd(f'{RISCV_GCC} {tmp_filename}.S -c -o {tmp_filename}.o')
    output = run_cmd(f'{RISCV_OBJDUMP} -d {tmp_filename}.o')
    run_cmd(f'rm {tmp_filename}.S {tmp_filename}.o')

    return output


def assemble(insts: List[str]) -> List[str]:
    """assemble insts to codes"""
    output = __assemble(insts)
    pattern = r'^\s*[0-9a-f]+:\s+([0-9a-f]+)'
    return re.findall(pattern, output, re.MULTILINE)


def assemble_pp_code(insts: List[str]) -> List[str]:
    """assemble insts to pp codes"""
    output = __assemble(insts)
    pattern = r'^\s*[0-9a-f]+:\s+(.*)'
    return re.findall(pattern, output, re.MULTILINE)


def disassemble(codes: List[str]) -> List[str]:
    def to_little_endian(s):
        ss = [s[i:i + 2] for i in range(0, len(s), 2)]
        ss.reverse()
        return ''.join(ss)

    codes_le = [to_little_endian(s) for s in codes]
    hex_data = '\n'.join(codes_le)
    bin_data = bytes.fromhex(hex_data)
    tmp_filename = f'{OUTPUT_PATH / __generate_random_string()}'
    with open(f'{tmp_filename}.bin', 'wb') as file:
        file.write(bin_data)
    output = run_cmd(f'{RISCV_OBJDUMP} -D -b binary -m riscv -M numeric,no-aliases {tmp_filename}.bin')
    run_cmd(f'rm {tmp_filename}.bin')

    pattern = r'^\s*[0-9a-f]+:\s+[0-9a-f]+\s+(.*)'
    return re.findall(pattern, output, re.MULTILINE)
