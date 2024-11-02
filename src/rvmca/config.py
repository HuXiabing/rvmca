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
from pathlib import Path

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


_current_path = Path(os.path.abspath(__file__)).resolve()

# constant: tool dir/paths
PROJECT_PATH = _current_path.parent.parent.parent
TOOLS_PATH = PROJECT_PATH / "tools"
TESTS_PATH = PROJECT_PATH / "tests"

OUTPUT_PATH = PROJECT_PATH / 'output'
TESTS_OUTPUT_PATH = TESTS_PATH / 'output'
INPUT_PATH = PROJECT_PATH / 'input'
TESTS_INPUT_PATH = TESTS_PATH / 'input'

RISCV_TOOLCHAIN = 'riscv64-unknown-linux-gnu-'
RISCV_GCC = RISCV_TOOLCHAIN + 'gcc'
RISCV_OBJDUMP = RISCV_TOOLCHAIN + 'objdump'
