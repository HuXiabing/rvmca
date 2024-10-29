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
"""Basic Types"""

from enum import Enum


class IType(Enum):
    """The instruction type."""
    Normal = 0  # Normal instructions, e.g., add, mul.
    Branch = 1  # Branch instructions, e.g., beq, bne, blt.
    Jump = 2  # Jump instructions, e.g., jal, jalr.
    Load = 3  # Load instructions, e.g., ld, lw.
    Store = 4  # Store instructions, e.g., sd, sw.
    Amo = 5  # Amo instructions, e.g., amoadd.w.
    Lr = 6  # Load reserved instructions, e.g., lr.w, lr.d.
    Sc = 7  # Store conditional instructions, e.g., sc.w, sc.d.
    Fence = 8  # Fence instructions, e.g., fence rw,rw.
    FenceTso = 9  # fence.tso.
    FenceI = 10  # fence.i.
    Unknown = -1  # Unknown instruction.


class MoFlag(Enum):
    """Memory ordering flag."""
    Relax = 0
    Acquire = 1
    Release = 2
    Strong = 3


class EType(Enum):
    Unknown = -1
    Read = 1
    Write = 2
    ReadWrite = 3
    SC_Fail = 4
