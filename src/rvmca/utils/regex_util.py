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

import re


def findone(compile_string, dst_string, flags=""):
    matches = findall(compile_string, dst_string, flags=flags)
    assert len(matches) <= 1, f"matches (len: {len(matches)}): {matches}, compile_string: {compile_string}"
    if len(matches) == 0:
        return ""
    else:
        return matches[0]


def findall(compile_string, dst_string, flags=""):
    if flags == "":
        pattern = re.compile(compile_string)
    else:
        pattern = re.compile(compile_string, flags)
    matches = re.findall(pattern, dst_string)
    return matches


def sub(compile_string, replaced_string, dst_string, flags=""):
    if flags == "":
        pattern = re.compile(compile_string)
    else:
        pattern = re.compile(compile_string, flags)
    string_after = re.sub(pattern, replaced_string, dst_string)
    return string_after


def split_spaces(cmd):
    """
    split multiple whitespaces
    refer to: https://theprogrammingexpert.com/python-replace-multiple-spaces-with-one-space/
    """
    splits = cmd.split()
    return splits
