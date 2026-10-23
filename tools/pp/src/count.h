#ifndef COUNT_H
#define COUNT_H

/*
#define __COUNT_START x.mfspr a5, 268
#define __COUNT_END x.mfspr a0, 268
*/
#define __COUNT_START rdcycle t6
#define __COUNT_END rdcycle a0
#define __COUNT_END_CODE 0xc0002573   // csrr a0, cycle

#define PIPELINE_DEPTH 15
#define MAX_INSN 1024

/* Offsets are relative to sp after both stack allocations. */
#define PROFILE_SAVE_SIZE  256
#define PROFILE_WORK_SIZE 1024
#define PROFILE_START_SLOT (PROFILE_WORK_SIZE + PROFILE_SAVE_SIZE - 16)
#define PROFILE_T6_SLOT    (PROFILE_WORK_SIZE + PROFILE_SAVE_SIZE - 8)

#endif
