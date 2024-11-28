grammar Program;
options { language=Python3; }

//prog : (label | inst)+ ;
//inst : (rfmt | ifmt | mfmt | bfmt | jfmt | ufmt | amofmt | pseudo | inst_fence | inst_fencetso | inst_fencei) ';'? ; // ('[' PROC ']')? (rfmt | ifmt | mfmt) ';'? ;
//label: LABEL ':';

// each statetement is supposed to have an ending ';'
prog : (label | inst)+ ;
inst : (rfmt | ifmt | mfmt | bfmt | jfmt | ufmt | amofmt | pseudo | inst_fence | inst_fencetso | inst_fencei | inst_fp) ';'? ;
label: LABEL ':' ';'?;

// TODO: here is an workaround for 'or' inst parsing (actually it is a bug of current Antlr4)
rfmt: (R_FMT_NAME REG ',' REG ',' REG) | ('or' REG ',' REG ',' REG);
ifmt: I_FMT_NAME REG ',' REG ',' IMM ;
// sw.rl /home/apr/tools/mappo/dataset/input/dataset_riscv_litmus/ATOMICS/RELAX/PodRWPX/LB+poprl+popx_has_ppo_0.litmus sw.rl
//mfmt: (LD_NAME(MO_FLAG)? | SD_NAME(MO_FLAG)? | JALR) REG ',' IMM '(' REG ')' ;
mfmt: (LD_NAME | SD_NAME | JALR) REG ',' IMM '(' REG ')' ;
bfmt: B_FMT_NAME REG ',' REG ',' (LABEL | IMM);
jfmt: 'jal' REG ',' (LABEL | IMM)  ;
ufmt: U_FMT_NAME REG ',' IMM ;
amofmt: AMO_NAME(MO_FLAG)? REG ',' REG ',' IMM?'(' REG ')';
pseudo : inst_j | inst_jr | inst_nop | inst_bz | inst_mv | inst_ret | inst_neg | inst_bgtle;

inst_bz: BRANCH_PSEUDO_ZERO_NAME  REG ',' (LABEL | IMM);
inst_bgtle: BRANCH_PSEUDO_NAME REG ',' REG ',' (LABEL | IMM);
inst_j: 'j' (LABEL | IMM) ;
inst_jr: 'jr' REG ;
inst_mv: 'mv' REG ',' REG ;
inst_neg: NEG_NAME REG ',' REG ;
inst_nop: 'nop' ;
inst_ret: 'ret' ;
inst_fence: ('fence' mem_access_op ',' mem_access_op) | fence_single;
inst_fencetso : 'fence.tso' ;
fence_single:'fence';
inst_fencei: 'fence.i' ;
mem_access_op: FENCE_OP| mem_access_op_single;
mem_access_op_single: ('r' | 'w' | 'rw');
FENCE_OP: ('i' | 'o' |'io')?('r' | 'w' | 'rw');

inst_fp: inst_fcsr | inst_fscsr | inst_f_x | inst_x_f | inst_f_f | inst_x_f_f | inst_f_ldst | inst_f_f_f_f | inst_f_f_f;
inst_f_f_f:  FFF_NAME FREG ',' FREG ',' FREG;
inst_fcsr: FCSR_NAME REG;
inst_fscsr: FSCSR_NAME REG ',' REG;
inst_f_x:  FX_NAME FREG ',' REG;
inst_x_f:  XF_NAME REG ',' FREG;
inst_f_f: FF_NAME FREG ',' FREG;
inst_x_f_f: XFF_NAME REG ',' FREG ',' FREG;
inst_f_ldst: F_LDST_NAME FREG ',' IMM '(' REG ')' ;
inst_f_f_f_f: FFFF_NAME FREG ',' FREG ',' FREG ',' FREG;

NEG_NAME: 'neg' | 'negw';
FFF_NAME: 'fsub.d' | 'fsub.s' | 'fsqrt.d' | 'fsqrt.s' | 'fsgnjx.d' | 'fsgnjx.s' | 'fsgnj.d' | 'fsgnj.s' | 'fsgnjn.d' | 'fsgnjn.s' | 'fadd.d' | 'fadd.s' | 'fdiv.s' | 'fdiv.d' | 'fmax.d' | 'fmax.s' | 'fmin.d' | 'fmin.s' | 'fmul.d' | 'fmul.s';
FCSR_NAME: 'frcsr' | 'frflags' | 'frrm';
FSCSR_NAME: 'fscsr' | 'fsflags' | 'fsrm';
FX_NAME: 'fmv.d.x' | 'fmv.w.x' | 'fcvt.d.l' | 'fcvt.d.lu' | 'fcvt.d.w' | 'fcvt.d.wu' | 'fcvt.s.l' | 'fcvt.s.lu' | 'fcvt.s.w' | 'fcvt.s.wu';
XF_NAME: 'fclass.d' | 'fclass.s' | 'fmv.x.d' | 'fmv.x.w' | 'fcvt.l.d' | 'fcvt.l.s' | 'fcvt.lu.d' | 'fcvt.lu.s' | 'fcvt.w.d' | 'fcvt.w.s' | 'fcvt.wu.d' | 'fcvt.wu.s';
FF_NAME: 'fcvt.s.d' | 'fcvt.d.s' | 'fabs.d' | 'fabs.s' | 'fmv.d' | 'fmv.s' | 'fneg.d' | 'fneg.s';
XFF_NAME: 'feq.d' | 'feq.s' | 'flt.d' | 'flt.s' | 'fle.d' | 'fle.s';
F_LDST_NAME: 'fld' | 'fsd' | 'flw' | 'fsw';
FFFF_NAME: 'fmadd.d' | 'fmadd.s' | 'fmsub.d' | 'fmsub.s' | 'fnmadd.d' | 'fnmadd.s' | 'fnmsub.d' | 'fnmsub.s';

BRANCH_PSEUDO_ZERO_NAME: 'bnez' | 'beqz' | 'blez' | 'bgez' | 'bltz' | 'bgtz';
BRANCH_PSEUDO_NAME: 'bgt' | 'bgtu' | 'ble' | 'bleu' ;
JALR: 'jalr' ;

R_FMT_NAME : 'add' | 'addw' | 'and' | 'div' | 'divu' | 'divuw' | 'divw'  | 'mul' | 'mulh' | 'mulhsu' | 'mulhu' | 'mulw' | 'rem' | 'remu' | 'remuw' | 'remw'  | 'sll' | 'sllw' | 'slt' | 'sltu' | 'sra' | 'sraw' | 'srl' | 'srlw' | 'sub' | 'subw' | 'xor' ;
I_FMT_NAME : 'addi' | 'addiw' | 'andi' | 'ori' | 'slli' | 'slliw' | 'slti' | 'sltiu' | 'srai' | 'sraiw' | 'srli' | 'srliw' | 'xori' ;
B_FMT_NAME: 'beq' | 'bge' | 'bgeu' | 'blt' | 'bltu' | 'bne' ;
U_FMT_NAME: 'auipc' | 'lui' | 'li';

LD_NAME : 'lb' | 'lbu' | 'ld' | 'lh' | 'lhu' | 'lw' | 'lwu' | ('lr.w' | 'lr.d')MO_FLAG?;
SD_NAME : 'sb' | 'sd' | 'sh' | 'sw' ;
AMO_NAME : 'amoadd.d' | 'amoadd.w' | 'amoand.d' | 'amoand.w' | 'amomax.d' | 'amomax.w' | 'amomaxu.d' | 'amomaxu.w' | 'amomin.d' | 'amomin.w' | 'amominu.d' | 'amominu.w' | 'amoor.d' | 'amoor.w' | 'amoswap.d' | 'amoswap.w' | 'amoxor.d' | 'amoxor.w' | 'sc.d' | 'sc.w';
// may be aq.rl
MO_FLAG : '.aq' | '.rl' | '.aqrl' | '.aq.rl' ;

REG : 'x0' | 'x1' | 'x2' | 'x3' | 'x4' | 'x5' | 'x6' | 'x7' | 'x8' | 'x9' | 'x10' | 'x11' | 'x12' | 'x13' | 'x14' | 'x15' | 'x16' | 'x17' | 'x18' | 'x19' | 'x20' | 'x21' | 'x22' | 'x23' | 'x24' | 'x25' | 'x26' | 'x27' | 'x28' | 'x29' | 'x30' | 'x31' | 'zero' | 'ra' | 'sp' | 'gp' | 'tp' | 't0' | 't1' | 't2' | 's0' | 's1' | 'a0' | 'a1' | 'a2' | 'a3' | 'a4' | 'a5' | 'a6' | 'a7' | 's2' | 's3' | 's4' | 's5' | 's6' | 's7' | 's8' | 's9' | 's10' | 's11' | 't3' | 't4' | 't5' | 't6';
FREG : 'f0' | 'f1' | 'f2' | 'f3' | 'f4' | 'f5' | 'f6' | 'f7' | 'f8' | 'f9' | 'f10' | 'f11' | 'f12' | 'f13' | 'f14' | 'f15' | 'f16' | 'f17' | 'f18' | 'f19' | 'f20' | 'f21' | 'f22' | 'f23' | 'f24' | 'f25' | 'f26' | 'f27' | 'f28' | 'f29' | 'f30' | 'f31' | 'ft0' | 'ft1' | 'ft2' | 'ft3' | 'ft4' | 'ft5' | 'ft6' | 'ft7' | 'fs0' | 'fs1' | 'fa0' | 'fa1' | 'fa2' | 'fa3' | 'fa4' | 'fa5' | 'fa6' | 'fa7' | 'fs2' | 'fs3' | 'fs4' | 'fs5' | 'fs6' | 'fs7' | 'fs8' | 'fs9' | 'fs10' | 'fs11' | 'ft8' | 'ft9' | 'ft10' | 'ft11';
LABEL : LETTER (LETTER | DIGIT | '_')* ;
IMM : ('+'|'-')? (([0-9]+) | (('0x')[0-9a-f]+));

fragment LETTER : LOWER_LETTER | UPPER_LETTER;
fragment LOWER_LETTER : 'a'..'z';
fragment UPPER_LETTER : 'A'..'Z';
fragment DIGIT : '0'..'9' ;

/* Comments and Useless Characters */
LINE_COMMENT : '//' .*? '\r'? '\n' -> skip; // Match "//" stuff '\n'
LINE_COMMENT2 : '#' .*? '\r'? '\n' -> skip; // Match "#" stuff '\n'
COMMENT : '/*' .*? '*/' -> skip; // Match "/*" stuff "*/"
// other comment /home/apr/tools/mappo/dataset/input/dataset_riscv_litmus_repair/HAND/LR-SC-diff-loc1_no_ppo_0.litmus
OTHER_COMMENT : '(*' .*? '*)' -> skip; // Match "/*" stuff "*/"
WS : [ \t\r\n]+ -> skip; // skip spaces, tabs, newlines