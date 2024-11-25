    .option pic
	.attribute arch, "rv64i2p1_m2p0_a2p1_f2p2_d2p2_zicsr2p0_zifencei2p0"
	.attribute unaligned_access, 0
	.attribute stack_align, 16
	.section __profile, "ax"
	.align	2
	.globl	rvmca_block_begin
	.globl	rvmca_block_end
	.globl  main
	.globl  rvmca_init
main:
rvmca_init:
#INIT#
rvmca_block_begin:
#CODE#
rvmca_block_end:
    ret
fail:
    ret