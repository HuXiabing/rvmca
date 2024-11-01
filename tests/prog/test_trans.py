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
from rvmca.prog import *
from rvmca.trans.compile import assemble_code
from rvmca.utils.file_util import *
from rvmca.config import *
from rvmca.utils.cmd_util import run_cmd

all_tests = list_files(INPUT_PATH / 'dv', '.S')


class TestTrans:

    def test_one_case_with_name(self):
        filepath = '/home/xuezheng/PycharmProjects/rvmca/tests/input/dv/test806.S'
        self.test_one_case(filepath)

    @pytest.mark.parametrize('filepath', all_tests)
    def test_one_case(self, filepath):
        # read file
        print(f'transform [{filepath}]')
        test_name = filepath.split('/')[-1].replace('.S', '')
        content = read_file(filepath) + '\n'
        failed = False
        error_msg = ""
        try:
            # transform block
            print('<Block>:')
            print(content)
            prog = parse_program(content)
            prog = remap_regs_for_block(prog)
            prog = zero_imm_for_block(prog)
            prog = legalize_jump_and_branch(prog)
            print('<New Block>:')
            print(prog.code)
            init_insts = init_states_for_block(prog, name=test_name)
            code = [inst.code for inst in init_insts]
            code.append('rdcycle a5')
            code.extend([inst.code for inst in prog.insts])
            print('\n<New Block with init code>:')
            code = '\n'.join(code)
            print(code)
            assemble_code(code, test_name)

            # run new block with pp
            result = run_cmd(f"qemu-riscv64 {TOOLS_PATH / 'pp' / 'pp'} {OUTPUT_PATH / test_name}.code")

            if not result:
                run_cmd(f"mv {OUTPUT_PATH / test_name}.code {OUTPUT_PATH / test_name}.code.error")
            assert result, "Error: pp fails."
        except Exception as e:
            print(e)
            error_msg = e
            failed = True
        finally:
            rm_file(f"{OUTPUT_PATH / test_name}.o")
            rm_file(f"{OUTPUT_PATH / test_name}.S")
            rm_file(f"{OUTPUT_PATH / test_name}")
            if not failed:
                print(f'Successfully!\n')
            else:
                raise AssertionError(error_msg)

    def test_400_perlbench(self):
        directory = INPUT_PATH / 'spec06' / '400_perlbench'
        for file in list_files(directory, '.S'):
            content = read_file(file) + '\n'
            prog = parse_program(content)
            print('\nOriginal program:')
            print(prog)
            prog = remap_regs_for_block(prog)
            print('\nRemap registers:')
            print(prog)

            print('\nInit code:')
            inits = init_states_for_block(prog)
            print('\n')
            for inst in inits:
                print(inst)

            print('\nZero immediate:')
            prog = zero_imm_for_block(prog)
            print(prog)

    def test_compile(self):
        directory = INPUT_PATH / 'spec06' / '400_perlbench'
        for file in list_files(directory, '.S'):
            content = read_file(file) + '\n'
            prog = parse_program(content)
            prog = remap_regs_for_block(prog)
            inits = init_states_for_block(prog)
            prog = zero_imm_for_block(prog)

            from rvmca.trans.compile import compile_block

            compile_block(prog, 'test1')

    def test_init_addr_reg(self):
        filename = INPUT_PATH / 'spec06' / '400_perlbench' / '1.S'
        content = read_file(filename) + '\n'
        prog = parse_program(content)
        prog = remap_regs_for_block(prog)
        # prog = zero_imm_for_block(prog)
        prog = legalize_jump_and_branch(prog)
        init_insts = init_states_for_block(prog)
        code = [inst.code for inst in init_insts]
        code.append('rdcycle a5')
        code.extend([inst.code for inst in prog.insts])
        print(prog.code)
        assemble_code('\n'.join(code), 'test')
