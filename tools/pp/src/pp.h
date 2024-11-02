#ifndef PP_H
#define PP_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include "count.h"

long profile0();
long profileN();

void init_fpu();

extern uint32_t profile_insn_start;
extern uint32_t profile_insn_init;

#define ENABLE_FPU asm volatile("fadd.d f0,f0,f0\n" :::"memory");
#define ENABLE_VPU asm volatile("vsetvli x0, x0, e32, ta, ma\n" :::"memory");

#define MATCH_JALR 0x67
#define MASK_JALR  0x707f
#define MATCH_JAL 0x6f
#define MASK_JAL  0x7f

#endif