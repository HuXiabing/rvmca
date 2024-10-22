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

"""Register Class Definition"""


class Reg:
    def __init__(self, id: int = 0):
        assert 0 <= id < 32, f'invalid register id {id} (0<=id<32)'
        self.id = id

    @property
    def name(self):
        return xregs_numeric[self.id]

    @property
    def abi_name(self):
        return xregs_abi[self.id]

    def __repr__(self):
        return self.name
        # return self.abi_name


xregs_numeric = [f'x{i}' for i in range(32)]

xregs_abi = [
    "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2",
    "s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5",
    "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7",
    "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6"
]


def find_reg_by_name(name: str):
    """
    Find the register object by name.

    Parameters
    ----------
    name:str numeric or abi register name.

    Returns
    -------
    A pre-defined corresponding register object in XRegs.

    """
    assert name in xregs_numeric + xregs_abi, f"invalid register name {name}"
    idx = (xregs_numeric + xregs_abi).index(name) % 32
    return Reg(idx)


def find_reg_idx_by_name(name: str):
    return (xregs_numeric + xregs_abi).index(name) % 32
