	.file	"temp.c"
	.option pic
	.attribute arch, "rv64i2p1_m2p0_a2p1_f2p2_d2p2_zicsr2p0_zifencei2p0"
	.attribute unaligned_access, 0
	.attribute stack_align, 16
	.text
	.align	2
	.globl	init_fpu
	.type	init_fpu, @function
init_fpu:
	flw	f0,.LC0,a5
    flw	f1,.LC0,a5
    fadd.s f2, f0, f1
    fadd.s f3, f0, f1
    fadd.s f4, f0, f1
    fadd.s f5, f0, f1
    fadd.s f6, f0, f1
    fadd.s f7, f0, f1
    fadd.s f8, f0, f1
    fadd.s f9, f0, f1
    fadd.s f10, f0, f1
    fadd.s f11, f0, f1
    fadd.s f12, f0, f1
    fadd.s f13, f0, f1
    fadd.s f14, f0, f1
    fadd.s f15, f0, f1
    fadd.s f16, f0, f1
    fadd.s f17, f0, f1
    fadd.s f18, f0, f1
    fadd.s f19, f0, f1
    fadd.s f20, f0, f1
    fadd.s f21, f0, f1
    fadd.s f22, f0, f1
    fadd.s f23, f0, f1
    fadd.s f24, f0, f1
    fadd.s f25, f0, f1
    fadd.s f26, f0, f1
    fadd.s f27, f0, f1
    fadd.s f28, f0, f1
    fadd.s f29, f0, f1
    fadd.s f30, f0, f1
    fadd.s f31, f0, f1
	ret
.LFE0:
	.size	init_fpu, .-init_fpu
	.section	.rodata.cst4,"aM",@progbits,4
	.align	2
.LC0:
	.word	1056964608
	.ident	"GCC: (Buildroot 2021.11-11272-ge2962af) 13.2.0"
	.section	.note.GNU-stack,"",@progbits
