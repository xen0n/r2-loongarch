#ifndef _R_LOONGARCH_H_
#define _R_LOONGARCH_H_

#include <inttypes.h>

typedef uint32_t la_insn_t;
typedef uint32_t la_opcode_t;
typedef uint32_t la_sel_t;
typedef uint8_t la_reg_t;

enum la_insn_format_t {
    LA_INSN_FORMAT_UNKNOWN,
    LA_INSN_FORMAT_RR,
    LA_INSN_FORMAT_RRR,
    LA_INSN_FORMAT_FFFF,
    LA_INSN_FORMAT_RRI6,
    LA_INSN_FORMAT_RRI8,
    LA_INSN_FORMAT_RRI12,
    LA_INSN_FORMAT_RRI6I6,
    LA_INSN_FORMAT_RRI14,
    LA_INSN_FORMAT_RRI16,
    LA_INSN_FORMAT_AUI20,
    LA_INSN_FORMAT_RI21,
    LA_INSN_FORMAT_I25,
    LA_INSN_FORMAT_LAST
};

typedef uint32_t la_render_flag_t;
#define RENDER_FLAG_PRINT_IMM_HEX   0x1
#define RENDER_FLAG_PRINT_IMM_SIGN  0x2
#define RENDER_FLAG_IMM_MINUS_32    0x4
#define RENDER_FLAG_IMM_SHL_2       0x8
#define RENDER_FLAG_RD_IS_FPR       0x10
#define RENDER_FLAG_RJ_IS_FPR       0x20
#define RENDER_FLAG_RK_IS_FPR       0x40
#define RENDER_FLAG_LOAD_STORE      0x80

struct _la_format_rr {
    la_opcode_t opcode;
    la_sel_t sel;
    la_reg_t rd;
    la_reg_t rj;
};

struct _la_format_rrr {
    la_opcode_t opcode;
    la_sel_t sel;
    la_reg_t rd;
    la_reg_t rj;
    la_reg_t rk;
};

struct _la_format_ffff {
    la_opcode_t opcode;
    la_sel_t sel;
    la_reg_t rd;
    la_reg_t rj;
    la_reg_t rk;
    la_reg_t ra;
};

struct _la_format_rri6 {
    la_opcode_t opcode;
    la_sel_t sel;
    la_reg_t rd;
    la_reg_t rj;
    uint8_t imm;
};

struct _la_format_rri8 {
    la_opcode_t opcode;
    la_sel_t sel;
    la_reg_t rd;
    la_reg_t rj;
    uint8_t imm;
};

struct _la_format_rri12 {
    la_opcode_t opcode;
    la_sel_t sel;
    la_reg_t rd;
    la_reg_t rj;
    uint16_t imm;
};

struct _la_format_rri6i6 {
    la_opcode_t opcode;
    la_sel_t sel;
    la_reg_t rd;
    la_reg_t rj;
    uint8_t imm1;
    uint8_t imm2;
};

struct _la_format_rri14 {
    la_opcode_t opcode;
    la_sel_t sel;
    la_reg_t rd;
    la_reg_t rj;
    uint16_t imm;
};

struct _la_format_rri16 {
    la_opcode_t opcode;
    la_reg_t rd;
    la_reg_t rj;
    uint16_t imm;
};

struct _la_format_aui20 {
    la_opcode_t opcode;
    la_sel_t sel;
    la_reg_t rd;
    uint32_t imm;
};

struct _la_format_ri21 {
    la_opcode_t opcode;
    la_reg_t rj;
    uint32_t imm;
};

struct _la_format_i25 {
    la_opcode_t opcode;
    la_sel_t sel;
    uint32_t imm;
};

struct la_op {
    const char *mnemonic;
    enum la_insn_format_t fmt;
    la_render_flag_t render_flags;
    union {
        la_insn_t unknown;
#define FMT(x) struct _la_format_ ## x x
        FMT(rr);
        FMT(rrr);
        FMT(ffff);
        FMT(rri6);
        FMT(rri8);
        FMT(rri12);
        FMT(rri6i6);
        FMT(rri14);
        FMT(rri16);
        FMT(aui20);
        FMT(ri21);
        FMT(i25);
#undef FMT
    } insn;
};
#endif  /* _R_LOONGARCH_H_ */
