# MIT License
#
# Copyright (c) 2023 Xuezheng (xuezhengxu@126.com)
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

"""Global Variable Dictionary"""
import os

from rvmca.utils import dir_util
import platform

REG_SIZE = 64

READS_PERMUTATION_REDUCTION = True
def init():
    """Initialize the global variable dictionary."""
    global _global_dict
    _global_dict = {}


def reset():
    """Reset the global variable dictionary."""
    _global_dict.clear()


def set_var(key: str, value):
    """Set the global variable `key` to `value`.
    as set() will conflict with the following set() method (list to set). So I change the name from set to set_val

    Parameters
    ----------
    key : str
        The name of the variable to set.
    value
        The value to be set.
    """
    _global_dict[key] = value


def get_var(key: str):
    """It returns the value of the global variable `key`.

    Parameters
    ----------
    key : str
        The name of the variable.

    Returns
    -------
    Any
        The value of the global variable `key`.
    """
    try:
        return _global_dict[key]
    except KeyError:
        print(f"fail to read {key}")


def has(key: str):
    """True if `key` in global variables, False otherwise.

    Parameters
    ----------
    key: str
        The variable name.

    Returns
    -------
    bool
        True if `key` in global variables, False otherwise.
    """
    return key in _global_dict.keys()


CUR_DIR = dir_util.get_cur_dir(__file__)

# constant: tool dir/paths
TOOL_DIR = os.path.join(CUR_DIR, "../../tools")
GLIBC_VERSION = platform.platform()[-9:]
# HERD7_PATH = shutil.which("herd7")
# assert HERD7_PATH is not None
# HERD7_PATH = os.path.join("/home/xuezheng/.local/opt/herdtools7/bin//", "herd7")
HERD7_PATH = os.path.join(TOOL_DIR, 'herdtools', GLIBC_VERSION, 'herd7')

#
OUTPUT_DIR = os.path.join(CUR_DIR, "../../output")
dir_util.mk_dir_from_dir_path(OUTPUT_DIR)

TEST_DIR = os.path.join(CUR_DIR, "../../tests")