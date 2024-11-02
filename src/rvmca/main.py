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
"""Main Entry Point"""

import sys
import os
import argparse

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

if __name__ == '__main__':
    from rvmca.config import *

    parser = argparse.ArgumentParser(description='RVMCA: RISC-V Machine Code Analyzer')
    parser.add_argument('input_file', help='input file')

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-p', '--profile', help='transform for profiling')
    group.add_argument('-rs', '--random_schedule', help='transform for random scheduling')
    parser.add_argument('-m', '--max', help='max number of output files for scheduling', type=int, default=10)

    args = parser.parse_args()

    from rvmca.utils.dir_util import mk_dir_from_dir_path

    mk_dir_from_dir_path(OUTPUT_PATH)

    from rvmca.trans import transform_for_profiling, transform_for_random_scheduling

    if args.profile:
        transform_for_profiling(args.input_file)
    elif args.random_schedule:
        if args.max <= 0:
            print(f'Error: invalid option --max {args.max} (should be greater then 0).')
            exit(1)
        transform_for_random_scheduling(args.input_file, limit=args.max)
