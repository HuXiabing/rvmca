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

_xregs_numeric = [f'x{i}' for i in range(32)]
_fregs_numeric = [f'f{i}' for i in range(32)]

_xregs_abi = [
    "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2",
    "s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5",
    "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7",
    "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6"
]

_fregs_abi = ['ft0', 'ft1', 'ft2', 'ft3', 'ft4', 'ft5', 'ft6', 'ft7',
              'fs0', 'fs1', 'fa0', 'fa1', 'fa2', 'fa3', 'fa4', 'fa5',
              'fa6', 'fa7', 'fs2', 'fs3', 'fs4', 'fs5', 'fs6', 'fs7',
              'fs8', 'fs9', 'fs10', 'fs11', 'ft8', 'ft9', 'ft10', 'ft11']

_all_regs_numeric = _xregs_numeric + _fregs_numeric
_all_regs_abi = _xregs_abi + _fregs_abi


class Reg:
    def __init__(self, id: int = 0):
        assert 0 <= id < len(_all_regs_numeric), f'invalid register id {id}'
        self.id = id

    @property
    def name(self):
        return _all_regs_numeric[self.id]

    @property
    def abi_name(self):
        return _all_regs_abi[self.id]

    def __repr__(self):
        return self.name

    def __eq__(self, other):
        if isinstance(other, Reg):
            return self.id == other.id
        return False

    def __hash__(self):
        return hash(self.id)


XREG = [Reg(i) for i in range(32)]
FREG = [Reg(i + 32) for i in range(32)]


def find_reg_by_name(name: str):
    """
    Find the register object by name.

    Parameters
    ----------
    name:str numeric or abi register name.

    Returns
    -------
    A pre-defined corresponding register object\.

    """
    if name is None:
        return None
    assert name in _all_regs_numeric + _all_regs_abi, f"invalid register name {name}"
    for r in XREG + FREG:
        if r.name == name or r.abi_name == name:
            return r
    return None


def bitvec_to_reg(bitvec) -> Reg:
    return find_reg_by_name(str(bitvec).split('_')[0])
