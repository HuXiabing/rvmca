#include "count.h"
	.option pic
	.attribute arch, "rv64i2p1_m2p0_a2p1_f2p2_d2p2_zicsr2p0_zifencei2p0"
	.attribute unaligned_access, 0
	.attribute stack_align, 16
	.section __profile, "axw"
	.align	2
	.globl	profile0
	.type	profile0, @function
profile0:
	fence
	__COUNT_START
	__COUNT_END
	fence
	sub	a0,a0,a5
	ret
	.globl	profileN
	.globl  profile_insn_start
	.type	profileN, @function
profileN:
	fence
	__COUNT_START
profile_insn_start:
	.rept 200
	nop
	.endr
	fence
	sub	a0,a0,a5
	ret
