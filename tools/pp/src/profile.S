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

	.rept PIPELINE_DEPTH
	nop
	.endr

	__COUNT_END
	fence
	sub	a0,a0,a5
	ret
	.globl	profileN
	.globl  profile_insn_start, profile_insn_init
	.type	profileN, @function
profileN:
	fence
	addi sp, sp, -96
	sd s0, 0(sp)
	sd s1, 8(sp)
	sd s2, 16(sp)
	sd s3, 24(sp)
	sd s4, 32(sp)
	sd s5, 40(sp)
	sd s6, 48(sp)
	sd s7, 56(sp)
	sd s8, 64(sp)
	sd s9, 72(sp)
	sd s10, 80(sp)
	sd s11, 88(sp)
	addi sp, sp, -0x400
profile_insn_init:
	.rept MAX_INSN
	nop
	.endr
	fence
	__COUNT_START
	.rept PIPELINE_DEPTH
	nop
	.endr
profile_insn_start:
	.rept MAX_INSN
	nop
	.endr
	fence
	sub	a0,a0,a5
	addi sp, sp, 0x400
	ld s0, 0(sp)
	ld s1, 8(sp)
	ld s2, 16(sp)
	ld s3, 24(sp)
	ld s4, 32(sp)
	ld s5, 40(sp)
	ld s6, 48(sp)
	ld s7, 56(sp)
	ld s8, 64(sp)
	ld s9, 72(sp)
	ld s10, 80(sp)
	ld s11, 88(sp)
	addi sp, sp, 96
	ret
