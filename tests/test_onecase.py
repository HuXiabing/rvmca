from rvmca.analysis import CFG, path_to_ssa, DDG, RVFG
from rvmca.trans.prof import *
from rvmca.trans.sched import *
from rvmca.utils.file_util import *
from rvmca.config import *
import os
from typing import Dict, Any, List


def test_onecase():
    # blocks = "add a5,s2,a5\nsb zero,0(a5)" 
    # add a5,s2,a5
    # blocks = "sw t3,0(t5)\\nld t3,0(t0)\\naddi t5,zero,3\\nadd t3,t3,a7\\nsb t5,0(t3)\\nld t5,0(a4)\\nadd t5,t5,a5\\nlw s5,0(t5)\\nld t3,368(s0)\\nld s11,0(s4)\\nadd t3,t3,a5\\nlw s8,0(t3)\\nlw t3,0(s11)\\naddw t3,t3,s8".replace('\\n', '\n')
    
    # blocks = 'sw a0,0(t2)\\nld a5,0(s6)\\nsb zero,0(a5)\\nld a5,0(t6)\\nlw a4,16(a5)'.replace('\\n','\n')
    # blocks = 'lh a5,96(t5)\\ndivw t4,a2,a5\\nmulw a5,a5,t3\\nsw t4,0(t2)\\nsw a5,0(t0)'.replace('\\n','\n')
    # blocks = 'lw a5,44(s4)\\naddi s1,zero,8\\naddi a4,zero,2\\ndivw s1,a5,s1\\nremw s5,a5,a4\\nremw s1,s1,a4\\naddi s5,s5,-1\\nsltiu s5,s5,1\\naddi s1,s1,-1\\nsltiu s1,s1,1'.replace('\\n','\n')
    # blocks = "addi a5,zero,34\\nsb a5,0(s2)\\nld s1,120(sp)\\nld s3,104(sp)\\nld s5,88(sp)\\nld s8,64(sp)\\nld s9,56(sp)\\nld s10,48(sp)\\nld s11,40(sp)\\naddi s2,s2,1\\nsb zero,0(s2)\\nld a5,0(s6)\\nsub a0,s2,s4\\nadd s7,a0,s7\\nsd s7,8(a5)\\nld ra,136(sp)\\nld s0,128(sp)\\nld s2,112(sp)\\nld s4,96(sp)\\nld s6,80(sp)\\nld s7,72(sp)\\naddiw a0,a0,0\\naddi sp,sp,144".replace('\\n', '\n')
    # blocks = "lw a5,-4(s5)\\nsd a0,1028(s5)"
    # blocks = "addi a5,a6,1\\nsd a5,-88(s0)\\nlbu a0,0(a6)"
    # blocks = "ld s0,320(sp)\\nld s1,312(sp)\\nld s2,304(sp)\\nld s3,296(sp)\\nld s4,288(sp)\\nld s5,280(sp)\\nld s6,272(sp)\\nld s7,264(sp)\\nld s8,256(sp)\\nld s9,248(sp)\\nld s10,240(sp)\\nld s11,232(sp)\\nsd zero,8(sp)".replace('\\n', '\n')
    # blocks = "lw a5,16(a4)\\naddiw s1,a5,1\\naddi a5,a5,1\\naddi a3,s1,0\\nsub s1,s1,a5\\nsw a3,16(a4)\\nsltu s1,zero,s1\\nld a3,16(s0)\\nld a5,0(a3)".replace('\\n', '\n')
    # blocks = "addi a4,a5,1\nsd a4,8(s0)\nlbu a5,0(a5)\nld a4,72(s1)\nslli a3,s2,0x3\nsltu a5,zero,a5\nadd a4,a4,a3\nsb a5,6(a4)\naddi s2,s2,1\n"
    # blocks = "addi a5,zero,0\nld a4,-96(s0)\nadd a5,a4,a5\nlbu a5,0(a5)\n\n"
    # blocks = "lhu a1,2(sp)\nlui a4,0x1\naddiw a4,a4,-496\nmulw a1,a1,a4\nlhu a0,4(sp)\nlhu a2,6(sp)\nadd a4,s1,s3\nslliw a3,a0,0x4\nsubw a3,a3,a0\nslliw a3,a3,0x2\nslli a4,a4,0x4\nadd a4,s2,a4\nld s5,24(sp)\naddw a3,a3,a1\naddw a3,a2,a3\nmulw a3,a3,a6\nld s6,16(sp)\nsw a3,28(a4)\n"
    # blocks = "slli s10,a3,0x2\nslli a3,a3,0x3\nadd s10,s2,s10\nadd s3,s2,a3\nlw a0,-4(s10)\naddi s10,s10,-4\naddi s3,s3,-8\n"
    # blocks = "addi sp,sp,-32\nsd ra,24(sp)\nsd s0,16(sp)\naddi s0,sp,32\nsd a0,-24(s0)\nld a5,-24(s0)\nld a5,80(a5)\naddi a0,a5,0\nld ra,24(sp)\nld s0,16(sp)\naddi sp,sp,32\n\n"

    blocks = "auipc a5,0x23b\nld a5,896(a5)\nlw a4,0(a5)"
    blocks = "auipc a0,0x24a\naddi a0,a0,1544\nlw a5,0(a0)"
    blocks =  "auipc a4,0x1f1\nld a4,2040(a4)\nld a5,0(a4)"
    blocks = "addi sp,sp,-16\nsd s0,0(sp)\nlui s0,0x387\nlbu a5,1840(s0)\nsd ra,8(sp)"
    blocks = "lui a4,0x2d3\nslli a3,a5,0x20\nsrli a5,a3,0x1e\naddi a4,a4,-1240\nadd a5,a5,a4\nlw a5,0(a5)"
    blocks = "lui a5,0x2a6\naddi a5,a5,1768\nld a4,0(a5)\nsw a0,4(a4)"
    
    blocks = "sd s6,120(gp)\\nsw s2,116(gp)\\nld s8,32(sp)\\nld s7,40(sp)\\nld a5,0(s0)\\nld a4,-952(gp)\\nsd s5,56(a5)\\nld a3,0(s0)\\nld a5,56(a3)\\nld a2,16(a3)"
    # blocks = "ld a4,0(a5)\\naddi a2,zero,2\\naddi a3,zero,-1\\nsw a3,16(a5)\\nsw a2,24(a5)\\nld a2,0(a4)\\nld a4,-952(gp)\\nld a3,-688(gp)\\nsd zero,8(a2)\\nld a4,0(a4)\\nsd s1,8(a4)"
    blocks = "ld a4,0(a5)\\nld a2,0(a4)\\nld a4,-952(gp)\\nld a3,-688(gp)\\nsd zero,8(a2)\\nld a4,0(a4)\\nsd s1,8(a4)"
    with open("temp.S", 'w', encoding='utf-8') as f:
        f.write(blocks.replace("\\n",'\n'))
    result = transform_for_profiling("temp.S",verbose = True)
    # transform_for_random_scheduling("temp.S", limit=10)
    print(result)

if __name__ == "__main__":
    test_onecase()
