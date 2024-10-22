# MIT License
#
# Copyright (c) 2022-2023 Xuezheng (xuezhengxu@126.com)
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

"""Progress Bar"""
import sys
import time


def print_progress_bar(iteration, total, prefix='', suffix='', decimals=1, length=50, fill='█', start_time=None):
    """Print Progress Bar
    Example:
    >>>    total = 100
    >>>    for i in range(total + 1):
    >>>        print_progress_bar(i, total, prefix='Progress:', suffix='Complete', length=50)
    """
    assert 0 <= iteration <= total
    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + '-' * (length - filled_length)
    output = f'\r{prefix} |{bar}| {percent}%'
    if iteration != total:
        output += f' {suffix}'
        if start_time:
            elapsed_time = "{: .1f}".format(time.time() - start_time)
            output += f' | Elapsed Time: {elapsed_time}s'

    sys.stdout.write(output)
