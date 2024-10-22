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

"""
Time utils.

usage example:
time_util.update_start_time()
…… (code to execute...)
print(f'time cost: {time_util.cal_time_cost()}')
"""

import time
from datetime import datetime, timedelta

start_time = -1


def get_cur_time_str():
    # datetime object containing current date and time
    now = datetime.now()
    dt_string = now.strftime("%Y/%m/%d %H:%M:%S")
    return dt_string


def get_cur_time():
    return datetime.now()


def update_start_time():
    global start_time
    start_time = time.time()


def cal_time_cost():
    assert start_time != -1
    time_cost = time.time() - start_time
    # print(f"time cost: {time_cost}s.")
    return time_cost


def parse_time_for_hms(time_string):
    parsed_time = datetime.strptime(time_string, "%H:%M:%S")
    return parsed_time


def get_time_cost(src_time, dst_time):
    # src_time and dst_time can be obtained by get_cur_time()
    timedelta = dst_time - src_time
    return timedelta.total_seconds()


def add_a_day(end_time):
    end_time = end_time + timedelta(days=1)
    return end_time
