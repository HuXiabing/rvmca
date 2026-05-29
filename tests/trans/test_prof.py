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
import json
from rvmca.analysis import CFG, path_to_ssa, DDG, RVFG
from rvmca.trans.prof import *
from rvmca.utils.file_util import *
from rvmca.config import *

all_tests = list_files(TESTS_INPUT_PATH / 'coremark-gcc14-O2', '.S')
# all_tests = list_files(TESTS_INPUT_PATH / 'manual', '.S')

class TestProf:

    def test_one_case_with_name(self):
        filepath = '/home/huxiabing/Documents/fail_coremark/test.S'
        # filepath = '/home/huxiabing/Documents/with_mem/coremark2/19.S'
        self.test_one_case(filepath)

    @pytest.mark.parametrize('filepath', all_tests)
    def test_one_case(self, filepath):
        transform_for_profiling(filepath)

    def test_400_perlbench(self):
        # directory = INPUT_PATH / 'spec06' / '400_perlbench'
        directory = '/home/huxiabing/Documents/fail_coremark'
        for file in list_files(directory, '.S'):
            transform_for_profiling(file)


    def test_coremark(self):
        polybench = ['polybench/2mm.json', 'polybench/3mm.json', 'polybench/adi.json', 'polybench/atax.json', 'polybench/bicg.json',
         'polybench/cholesky.json', 'polybench/correlation.json', 'polybench/covariance.json', 'polybench/deriche.json',
         'polybench/doitgen.json', 'polybench/durbin.json', 'polybench/fdtd-2d.json', 'polybench/floyd-warshall.json',
         'polybench/gemm.json', 'polybench/gemver.json', 'polybench/gesummv.json', 'polybench/gramschmidt.json',
         'polybench/heat-3d.json', 'polybench/jacobi-1d.json', 'polybench/jacobi-2d.json', 'polybench/lu.json',
         'polybench/ludcmp.json', 'polybench/mvt.json', 'polybench/nussinov.json', 'polybench/seidel-2d.json',
         'polybench/symm.json', 'polybench/syr2k.json', 'polybench/syrk.json', 'polybench/trisolv.json',
         'polybench/trmm.json']
        spec06 = ['spec06/400.perlbench.json', 'spec06/401.bzip2.json', 'spec06/403.gcc.json', 'spec06/410.bwaves.json', 'spec06/416.gamess.json', 'spec06/429.mcf.json', 'spec06/433.milc.json', 'spec06/434.zeusmp.json', 'spec06/435.gromacs.json', 'spec06/436.cactusADM.json', 'spec06/437.leslie3d.json', 'spec06/444.namd.json', 'spec06/445.gobmk.json', 'spec06/447.dealII.json', 'spec06/450.soplex.json', 'spec06/453.povray.json', 'spec06/454.calculix.json', 'spec06/456.hmmer.json', 'spec06/458.sjeng.json', 'spec06/459.GemsFDTD.json', 'spec06/462.libquantum.json', 'spec06/464.h264ref.json', 'spec06/465.tonto.json', 'spec06/470.lbm.json', 'spec06/471.omnetpp.json', 'spec06/473.astar.json', 'spec06/481.wrf.json', 'spec06/482.sphinx3.json', 'spec06/483.xalancbmk.json', 'spec06/998.specrand.json', 'spec06/999.specrand.json']
        spec17 = ['spec17/500.perlbench_r.json', 'spec17/502.gcc_r.json', 'spec17/503.bwaves_r.json', 'spec17/505.mcf_r.json', 'spec17/507.cactuBSSN_r.json', 'spec17/508.namd_r.json', 'spec17/510.parest_r.json', 'spec17/511.povray_r.json', 'spec17/519.lbm_r.json', 'spec17/520.omnetpp_r.json', 'spec17/521.wrf_r.json', 'spec17/523.xalancbmk_r.json', 'spec17/525.x264_r.json', 'spec17/526.blender_r.json', 'spec17/527.cam4_r.json', 'spec17/531.deepsjeng_r.json', 'spec17/538.imagick_r.json', 'spec17/541.leela_r.json', 'spec17/544.nab_r.json', 'spec17/548.exchange2_r.json', 'spec17/549.fotonik3d_r.json', 'spec17/554.roms_r.json', 'spec17/557.xz_r.json', 'spec17/600.perlbench_s.json', 'spec17/602.gcc_s.json', 'spec17/603.bwaves_s.json', 'spec17/605.mcf_s.json', 'spec17/607.cactuBSSN_s.json', 'spec17/619.lbm_s.json', 'spec17/620.omnetpp_s.json', 'spec17/621.wrf_s.json', 'spec17/623.xalancbmk_s.json', 'spec17/625.x264_s.json', 'spec17/627.cam4_s.json', 'spec17/628.pop2_s.json', 'spec17/631.deepsjeng_s.json', 'spec17/638.imagick_s.json', 'spec17/641.leela_s.json', 'spec17/644.nab_s.json', 'spec17/648.exchange2_s.json', 'spec17/649.fotonik3d_s.json', 'spec17/654.roms_s.json', 'spec17/657.xz_s.json', 'spec17/996.specrand_fs.json', 'spec17/997.specrand_fr.json', 'spec17/998.specrand_is.json', 'spec17/999.specrand_ir.json']

        files = ['coremark2.json', 'git.json', 'gzip.json', 'sqlite3.json'] + polybench + spec06 + spec17
        # files = ['coremark.json']
        # for file in files:
        #     filepath = '/home/huxiabing/Documents/raw_data(extract_from_app)/json/' + file
        #     with open(filepath, 'r') as f:
        #         blocks = json.load(f)
        #     success = 0
        #     failed = 0
        #     results = []
        #     print(len(blocks))
        #
        #     for idx, block in enumerate(blocks):
        #         # bin = block['binary'].split(' ')
        #         asm = block['asm'].replace('\\n', '\n')
        #         with open(f'{idx}.S', 'w', encoding='utf-8') as f:
        #             f.write(asm)
        #         try:
        #             result = transform_for_profiling(f'{idx}.S')
        #             results.append(result)
        #             if result['result']==None:
        #                 failed += 1
        #             else:
        #                 success += 1
        #         except Exception as e:
        #             failed += 1
        #             print(f"[FAIL] {idx}.S: {e}")
        #         rm_file(f'{idx}.S')
        #     with open(f'{file}_result.json', 'w+') as f:
        #         json.dump(results, f, indent=4)
        #
        #     print(f"\n运行完成：成功 {success} 个，失败 {failed} 个")
        for file in files:
            filepath = '/home/huxiabing/Documents/raw_data(extract_from_app)/json/' + file
            with open(filepath, 'r') as f:
                blocks = json.load(f)
            success = 0
            failed = 0

            # 创建结果文件并写入起始标记
            result_filename = f'{file[:-5]}_result.json'
            with open(result_filename, 'w', encoding='utf-8') as result_file:
                result_file.write('[\n')  # 开始JSON数组

            first_item = True

            for idx, block in enumerate(blocks):
                asm = block['asm'].replace('\\n', '\n')
                temp_filename = f'{idx}.S'

                with open(temp_filename, 'w', encoding='utf-8') as f:
                    f.write(asm)

                try:
                    result = transform_for_profiling(temp_filename)
                    if result and result.get('result') is not None:
                        success += 1
                    else:
                        failed += 1
                except Exception as e:
                    failed += 1
                    print(f"[FAIL] {idx}.S: {e}")

                # 立即写入当前结果
                with open(result_filename, 'a', encoding='utf-8') as result_file:
                    if not first_item:
                        result_file.write(',\n')
                    json.dump(result, result_file, indent=2)
                    first_item = False

                # 清理临时文件
                rm_file(temp_filename)

            # 完成JSON数组
            with open(result_filename, 'a', encoding='utf-8') as result_file:
                result_file.write('\n]')

            print(f"\n运行完成：成功 {success} 个，失败 {failed} 个")

    def test_polybench(self):
        polybench = ['polybench/2mm.json', 'polybench/3mm.json', 'polybench/adi.json', 'polybench/atax.json', 'polybench/bicg.json',
         'polybench/cholesky.json', 'polybench/correlation.json', 'polybench/covariance.json', 'polybench/deriche.json',
         'polybench/doitgen.json', 'polybench/durbin.json', 'polybench/fdtd-2d.json', 'polybench/floyd-warshall.json',
         'polybench/gemm.json', 'polybench/gemver.json', 'polybench/gesummv.json', 'polybench/gramschmidt.json',
         'polybench/heat-3d.json', 'polybench/jacobi-1d.json', 'polybench/jacobi-2d.json', 'polybench/lu.json',
         'polybench/ludcmp.json', 'polybench/mvt.json', 'polybench/nussinov.json', 'polybench/seidel-2d.json',
         'polybench/symm.json', 'polybench/syr2k.json', 'polybench/syrk.json', 'polybench/trisolv.json',
         'polybench/trmm.json']
        spec06 = ['spec06/400.perlbench.json', 'spec06/401.bzip2.json', 'spec06/403.gcc.json', 'spec06/410.bwaves.json', 'spec06/416.gamess.json', 'spec06/429.mcf.json', 'spec06/433.milc.json', 'spec06/434.zeusmp.json', 'spec06/435.gromacs.json', 'spec06/436.cactusADM.json', 'spec06/437.leslie3d.json', 'spec06/444.namd.json', 'spec06/445.gobmk.json', 'spec06/447.dealII.json', 'spec06/450.soplex.json', 'spec06/453.povray.json', 'spec06/454.calculix.json', 'spec06/456.hmmer.json', 'spec06/458.sjeng.json', 'spec06/459.GemsFDTD.json', 'spec06/462.libquantum.json', 'spec06/464.h264ref.json', 'spec06/465.tonto.json', 'spec06/470.lbm.json', 'spec06/471.omnetpp.json', 'spec06/473.astar.json', 'spec06/481.wrf.json', 'spec06/482.sphinx3.json', 'spec06/483.xalancbmk.json', 'spec06/998.specrand.json', 'spec06/999.specrand.json']
        spec17 = ['spec17/500.perlbench_r.json', 'spec17/502.gcc_r.json', 'spec17/503.bwaves_r.json', 'spec17/505.mcf_r.json', 'spec17/507.cactuBSSN_r.json', 'spec17/508.namd_r.json', 'spec17/510.parest_r.json', 'spec17/511.povray_r.json', 'spec17/519.lbm_r.json', 'spec17/520.omnetpp_r.json', 'spec17/521.wrf_r.json', 'spec17/523.xalancbmk_r.json', 'spec17/525.x264_r.json', 'spec17/526.blender_r.json', 'spec17/527.cam4_r.json', 'spec17/531.deepsjeng_r.json', 'spec17/538.imagick_r.json', 'spec17/541.leela_r.json', 'spec17/544.nab_r.json', 'spec17/548.exchange2_r.json', 'spec17/549.fotonik3d_r.json', 'spec17/554.roms_r.json', 'spec17/557.xz_r.json', 'spec17/600.perlbench_s.json', 'spec17/602.gcc_s.json', 'spec17/603.bwaves_s.json', 'spec17/605.mcf_s.json', 'spec17/607.cactuBSSN_s.json', 'spec17/619.lbm_s.json', 'spec17/620.omnetpp_s.json', 'spec17/621.wrf_s.json', 'spec17/623.xalancbmk_s.json', 'spec17/625.x264_s.json', 'spec17/627.cam4_s.json', 'spec17/628.pop2_s.json', 'spec17/631.deepsjeng_s.json', 'spec17/638.imagick_s.json', 'spec17/641.leela_s.json', 'spec17/644.nab_s.json', 'spec17/648.exchange2_s.json', 'spec17/649.fotonik3d_s.json', 'spec17/654.roms_s.json', 'spec17/657.xz_s.json', 'spec17/996.specrand_fs.json', 'spec17/997.specrand_fr.json', 'spec17/998.specrand_is.json', 'spec17/999.specrand_ir.json']

        files = ['git.json'] + polybench + spec06 + spec17

        for file in polybench:
            filepath = '/home/huxiabing/Documents/raw_data(extract_from_app)/json/' + file
            with open(filepath, 'r') as f:
                blocks = json.load(f)
            success = 0
            failed = 0

            # 创建结果文件并写入起始标记
            result_filename = f'/home/huxiabing/Documents/rvmca/tests/{file[:-5]}_result.json'
            with open(result_filename, 'w', encoding='utf-8') as result_file:
                result_file.write('[\n')  # 开始JSON数组

            first_item = True

            for idx, block in enumerate(blocks):
                asm = block['asm'].replace('\\n', '\n')
                temp_filename = f'{idx}.S'

                with open(temp_filename, 'w', encoding='utf-8') as f:
                    f.write(asm)

                try:
                    result = transform_for_profiling(temp_filename)
                    if result and result.get('result') is not None:
                        success += 1
                    else:
                        failed += 1
                except Exception as e:
                    failed += 1
                    print(f"[FAIL] {idx}.S: {e}")

                # 立即写入当前结果
                with open(result_filename, 'a', encoding='utf-8') as result_file:
                    if not first_item:
                        result_file.write(',\n')
                    json.dump(result, result_file, indent=2)
                    first_item = False

                # 清理临时文件
                rm_file(temp_filename)

            # 完成JSON数组
            with open(result_filename, 'a', encoding='utf-8') as result_file:
                result_file.write('\n]')

            print(f"\n运行完成：成功 {success} 个，失败 {failed} 个")
    def test_manual(self):
        directory = TESTS_INPUT_PATH / 'manual'
        for file in list_files(directory, '.S'):
            transform_for_profiling(file)

    def test_fail(self):
        # file = TESTS_INPUT_PATH / 'manual' / '5.S'
        file = TESTS_INPUT_PATH / 'coremark-gcc14-O2' / 'block-41.S'
        transform_for_profiling(file)

    def test_cfg(self):
        filepath = INPUT_PATH / 'test.S'
        content = read_file(filepath) + '\n'
        prog = parse_program(content)
        prog = remap_regs_for_block(prog)
        prog = zero_imm_for_block(prog)
        prog = legalize_jump_and_branch(prog)

        cfg = CFG(prog.insts)
        cfg.plot(OUTPUT_PATH / 'test')
        ssas = path_to_ssa(cfg.edges)
        print()
        print('\n'.join([str(ssa) for ssa in ssas]))

    def test_ddg_rvfg(self):
        filepath = INPUT_PATH / 'test.S'
        content = read_file(filepath) + '\n'
        prog = parse_program(content)
        prog = remap_regs_for_block(prog)
        prog = zero_imm_for_block(prog)
        prog = legalize_jump_and_branch(prog)

        cfg = CFG(prog.insts)
        cfg.plot(OUTPUT_PATH / 'test.cfg')
        ssas = path_to_ssa(cfg.edges)
        print()
        print('\n'.join([str(ssa) for ssa in ssas]))

        ddg = DDG(ssas)
        ddg.plot(OUTPUT_PATH / 'test.ddg')

        rvfg = RVFG(ssas)
        rvfg.plot(OUTPUT_PATH / 'test.rvfg')

    def test_tail_branch(self):
        test_file = INPUT_PATH / 'test_branch.S'
        transform_for_profiling(test_file)
