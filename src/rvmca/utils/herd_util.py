# MIT License
#
# Copyright (c) 2023 DehengYang (dehengyang@qq.com)
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

import os

from rvmca import config
from rvmca.comp.parse_result import parse_one_herd_output
from rvmca.litmus.litmus import LitmusResult, LitmusState
from rvmca.utils import dir_util, file_util, cmd_util


def run_herd(litmus_file_name, litmus_code, cat_file_path) -> LitmusResult:
    """
    Run herd.
    :param litmus_file_name: file name of the litmus test
    :param litmus_code: concrete code of the litmus file
    :param cat_file_path: path of CAT file
    :return: LitmusResult

    herd output example:
    Test 2+2Swap Allowed
    States 4
    0:x10=0; 0:x11=0; 1:x10=1; 1:x11=2; [x]=1; [y]=2;
    0:x10=0; 0:x11=2; 1:x10=0; 1:x11=2; [x]=1; [y]=1;
    0:x10=1; 0:x11=0; 1:x10=1; 1:x11=0; [x]=2; [y]=2;
    0:x10=1; 0:x11=2; 1:x10=0; 1:x11=0; [x]=2; [y]=1;
    Ok
    Witnesses
    Positive: 1 Negative: 3
    Condition exists ([x]=2 /\ [y]=2 /\ 0:x10=1 /\ 0:x11=0 /\ 1:x10=1 /\ 1:x11=0)
    Observation 2+2Swap Sometimes 1 3
    Time 2+2Swap 0.01
    Hash=760e481b3c7b9ad1c78990727e5fcf50
    """
    # TODO: need a more elegant way to set herd output path
    cur_dir = dir_util.get_cur_dir(__file__)
    output_dir = os.path.join(cur_dir, '../../../output', 'litmus_herd_result')
    dir_util.mk_dir_from_dir_path(output_dir)

    # save litmus code
    litmus_file_path = os.path.join(output_dir, litmus_file_name)
    file_util.write_str_to_file(litmus_file_path, litmus_code, False)

    # save herd output
    litmus_herd_result_path = os.path.join(output_dir, litmus_file_name + ".log")
    if cat_file_path is not None:
        cmd = f"{config.HERD7_PATH} {litmus_file_path} -model {cat_file_path}"
    else:
        cmd = f"{config.HERD7_PATH} {litmus_file_path}"
    output = cmd_util.run_cmd_with_output(cmd).strip()
    assert output, f'[ERROR] cmd has empty output: {cmd}'
    # print(f'[INFO] run herd cmd: {cmd}, output: {output}')
    file_util.write_str_to_file(litmus_herd_result_path, output, False)

    states, pos_cnt, neg_cnt, time_cost = parse_one_herd_output(output)
    states = [LitmusState(s) for s in states]
    states.sort(key=lambda s: str(s))
    return LitmusResult(litmus_file_name, states=states, pos_cnt=pos_cnt, neg_cnt=neg_cnt, time_cost=time_cost)
