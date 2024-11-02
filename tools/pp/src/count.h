#ifndef COUNT_H
#define COUNT_H

/*
#define __COUNT_START x.mfspr a5, 268
#define __COUNT_END x.mfspr a0, 268
*/
#define __COUNT_START rdcycle a5
#define __COUNT_END rdcycle a0
#define __COUNT_END_CODE 0xc0002573

#define PIPELINE_DEPTH 15
#define MAX_INSN 200

#endif