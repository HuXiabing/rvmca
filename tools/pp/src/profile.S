#include "count.h"
	.option pic
	.attribute arch, "rv64i2p1_m2p0_a2p1_f2p2_d2p2_zicsr2p0_zifencei2p0"
	.attribute unaligned_access, 0
	.attribute stack_align, 16
	/* Preserve the initialized t6; only the timestamp lives across the block.
	 * Both paths include the same store, load and nops in the timed interval.
	 * The block must restore sp and leave the context/timing slots intact.
	 */
	.macro profile_count_start
	sd t6, PROFILE_T6_SLOT(sp)
	fence
	__COUNT_START
	sd t6, PROFILE_START_SLOT(sp)
	ld t6, PROFILE_T6_SLOT(sp)
	.rept PIPELINE_DEPTH
	nop
	.endr
	fence
	.endm

	.macro profile_count_result
	fence
	ld t6, PROFILE_START_SLOT(sp)
	sub a0, a0, t6
	.endm

	.section __profile, "axw"
	.align	2
	.globl	profile0
	.type	profile0, @function
profile0:
	addi sp, sp, -PROFILE_SAVE_SIZE
	addi sp, sp, -PROFILE_WORK_SIZE
	profile_count_start
	__COUNT_END
	profile_count_result
	addi sp, sp, PROFILE_WORK_SIZE
	addi sp, sp, PROFILE_SAVE_SIZE
	ret
	.globl	profileN
	.globl  profile_insn_start, profile_insn_init
	.type	profileN, @function
profileN:
	fence
	addi sp, sp, -PROFILE_SAVE_SIZE
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
	fsd fs0, 96(sp)
	fsd fs1, 104(sp)
	fsd fs2, 112(sp)
	fsd fs3, 120(sp)
	fsd fs4, 128(sp)
	fsd fs5, 136(sp)
	fsd fs6, 144(sp)
	fsd fs7, 152(sp)
	fsd fs8, 160(sp)
	fsd fs9, 168(sp)
	fsd fs10, 176(sp)
	fsd fs11, 184(sp)
	sd ra, 192(sp)
	sd gp, 200(sp)
	sd tp, 208(sp)
	addi sp, sp, -PROFILE_WORK_SIZE
profile_insn_init:
	.rept MAX_INSN
	nop
	.endr
	profile_count_start
profile_insn_start:
	/* Include a slot for the injected end counter at maximum block length. */
	.rept MAX_INSN + 1
	nop
	.endr
	profile_count_result
	addi sp, sp, PROFILE_WORK_SIZE
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
	fld fs0, 96(sp)
	fld fs1, 104(sp)
	fld fs2, 112(sp)
	fld fs3, 120(sp)
	fld fs4, 128(sp)
	fld fs5, 136(sp)
	fld fs6, 144(sp)
	fld fs7, 152(sp)
	fld fs8, 160(sp)
	fld fs9, 168(sp)
	fld fs10, 176(sp)
	fld fs11, 184(sp)
	ld ra, 192(sp)
	ld gp, 200(sp)
	ld tp, 208(sp)
	addi sp, sp, PROFILE_SAVE_SIZE
	ret
