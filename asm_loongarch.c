// SPDX-License-Identifier: GPL-3.0-or-later

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>

#include "r_loongarch.h"

struct la_disasm_matcher {
    const char *mnemonic;
    enum la_insn_format_t fmt;
    la_insn_t match;
    la_insn_t mask;
    la_render_flag_t render_flags;
};

static const char *loongarch_reg_names_gpr[] = {
    "zero", "ra", "r2", "sp",   /* 0 .. 3 */
    "a0", "a1", "a2", "a3",     /* 4 .. 7 */
    "a4", "a5", "a6", "a7",     /* 8 .. 11 */
    "t0", "t1", "t2", "t3",     /* 12 .. 15 */
    "t4", "t5", "t6", "at",     /* 16 .. 19 */
    "r20", "r21", "s9", "s0",   /* 20 .. 23 */
    "s1", "s2", "s3", "s4",     /* 24 .. 27 */
    "s5", "s6", "s7", "s8"      /* 28 .. 31 */
};

static const char *loongarch_reg_names_fpr[] = {
    "f0", "f1", "f2", "f3",     /* 0 .. 3 */
    "f4", "f5", "f6", "f7",     /* 4 .. 7 */
    "f8", "f9", "f10", "f11",   /* 8 .. 11 */
    "f12", "f13", "f14", "f15", /* 12 .. 15 */
    "f16", "f17", "f18", "f19", /* 16 .. 19 */
    "f20", "f21", "f22", "f23", /* 20 .. 23 */
    "f24", "f25", "f26", "f27", /* 24 .. 27 */
    "f28", "f29", "f30", "f31"  /* 28 .. 31 */
};


/* Shorthands. */
#define UNK     LA_INSN_FORMAT_UNKNOWN
#define RR      LA_INSN_FORMAT_RR
#define RRR     LA_INSN_FORMAT_RRR
#define FFFF    LA_INSN_FORMAT_FFFF
#define RRI6    LA_INSN_FORMAT_RRI6
#define RRI8    LA_INSN_FORMAT_RRI8
#define RRI12   LA_INSN_FORMAT_RRI12
#define RRI6I6  LA_INSN_FORMAT_RRI6I6
#define RRI14   LA_INSN_FORMAT_RRI14
#define RRI16   LA_INSN_FORMAT_RRI16
#define AUI20   LA_INSN_FORMAT_AUI20
#define RI21    LA_INSN_FORMAT_RI21
#define I25     LA_INSN_FORMAT_I25
#define HEX     RENDER_FLAG_PRINT_IMM_HEX
#define JO      RENDER_FLAG_IMM_JUMP_OFFSET
#define M32     RENDER_FLAG_IMM_MINUS_32
#define SHL2    RENDER_FLAG_IMM_SHL_2
#define FD      RENDER_FLAG_RD_IS_FPR
#define FJ      RENDER_FLAG_RJ_IS_FPR
#define FK      RENDER_FLAG_RK_IS_FPR
#define FDJK    (FD | FJ | FK)
#define LS      RENDER_FLAG_LOAD_STORE

static const struct la_disasm_matcher loongarch_disasm_data[] = {
    /* mnemonic     fmt     match       mask */
    /* NOTE: to modify this, use the gen_match_masks.py and adjust */
    { "sext.h",     RR,     0x00005800, 0xfffffc00, 0 },
    { "sext.b",     RR,     0x00005c00, 0xfffffc00, 0 },
    { "addw",       RRR,    0x00100000, 0xffff8000, 0 },
    { "add",        RRR,    0x00108000, 0xffff8000, 0 },
    { "subw",       RRR,    0x00110000, 0xffff8000, 0 },
    { "sub",        RRR,    0x00118000, 0xffff8000, 0 },
    { "!selnez",    RRR,    0x00130000, 0xffff8000, 0 },
    { "!seleqz",    RRR,    0x00138000, 0xffff8000, 0 },
    { "!nor",       RRR,    0x00140000, 0xffff8000, 0 },
    { "and",        RRR,    0x00148000, 0xffff8000, 0 },
    { "or",         RRR,    0x00150000, 0xffff8000, 0 },
    { "xor",        RRR,    0x00158000, 0xffff8000, 0 },
    { "sll",        RRR,    0x00170000, 0xffff8000, 0 },
    { "sbs",        RRR,    0x00180000, 0xffff8000, 0 },
    { "srl",        RRR,    0x00190000, 0xffff8000, 0 },
    { "mul",        RRR,    0x001d8000, 0xffff8000, 0 },
    { "syscall",    RRR,    0x002b0000, 0xffffffff, 0 },
    { "ofs.w",      RRR,    0x002c8000, 0xffff8000, 0 },
    { "slliw",      RRI6,   0x00408000, 0xffff8000, M32 },
    { "slli",       RRI6,   0x00410000, 0xffff0000, 0 },
    { "srliw",      RRI6,   0x00448000, 0xffff8000, M32 },
    { "srli",       RRI6,   0x00450000, 0xffff0000, 0 },
    { "sraiw",      RRI6,   0x00488000, 0xffff8000, M32 },
    { "srai",       RRI6,   0x00490000, 0xffff0000, 0 },
    { "roriw",      RRI6,   0x004c8000, 0xffff8000, M32 },
    { "rori",       RRI6,   0x004d0000, 0xffff0000, 0 },
    { "ext.w",      RRI6I6, 0x00608000, 0xffe08000, M32 },
    { "mask",       RRI6I6, 0x00c00000, 0xffc00000, 0 },
    { "fadd.d",     RRR,    0x01010000, 0xffff8000, FDJK },
    { "fsub.d",     RRR,    0x01030000, 0xffff8000, FDJK },
    { "fmul.d",     RRR,    0x01050000, 0xffff8000, FDJK },
    { "fdiv.d",     RRR,    0x01070000, 0xffff8000, FDJK },
    { "slti",       RRI12,  0x02000000, 0xffc00000, 0 },
    { "sltiu",      RRI12,  0x02400000, 0xffc00000, HEX },
    { "addiw",      RRI12,  0x02800000, 0xffc00000, 0 },
    { "addi",       RRI12,  0x02c00000, 0xffc00000, 0 },
    { "ati",        RRI12,  0x03000000, 0xffc00000, HEX },
    { "andi",       RRI12,  0x03400000, 0xffc00000, HEX },
    { "ori",        RRI12,  0x03800000, 0xffc00000, HEX },
    { "xori",       RRI12,  0x03c00000, 0xffc00000, HEX },
    { "aui",        AUI20,  0x14000000, 0xfe000000, 0 },
    { "ahi",        AUI20,  0x16000000, 0xfe000000, HEX },
    { "auipc",      AUI20,  0x1c000000, 0xfe000000, HEX },
    { "lw.2",       RRI14,  0x24000000, 0xff000000, SHL2|LS },
    { "sw.2",       RRI14,  0x25000000, 0xff000000, SHL2|LS },
    { "ld.2",       RRI14,  0x26000000, 0xff000000, SHL2|LS },
    { "sd.2",       RRI14,  0x27000000, 0xff000000, SHL2|LS },
    { "lb",         RRI12,  0x28000000, 0xffc00000, LS },
    { "lh",         RRI12,  0x28400000, 0xffc00000, LS },
    { "lw",         RRI12,  0x28800000, 0xffc00000, LS },
    { "ld",         RRI12,  0x28c00000, 0xffc00000, LS },
    { "sb",         RRI12,  0x29000000, 0xffc00000, LS },
    { "sh",         RRI12,  0x29400000, 0xffc00000, LS },
    { "sw",         RRI12,  0x29800000, 0xffc00000, LS },
    { "sd",         RRI12,  0x29c00000, 0xffc00000, LS },
    { "lb.2",       RRI12,  0x2a000000, 0xffc00000, LS },
    { "lh.2",       RRI12,  0x2a400000, 0xffc00000, LS },
    { "fld",        RRI12,  0x2b800000, 0xffc00000, FD|LS },
    { "fsd",        RRI12,  0x2bc00000, 0xffc00000, FD|LS },
    { "beqz",       RI21,   0x40000000, 0xfc000000, JO },
    { "bnez",       RI21,   0x44000000, 0xfc000000, JO },
    { "!bfp",       RI21,   0x48000000, 0xfc000000, JO },
    { "jalr",       RR,     0x4c000000, 0xfffffc00, 0 },
    { "j",          I25,    0x50000000, 0xfc000000, JO },
    { "jal",        I25,    0x54000000, 0xfc000000, JO },
    { "beq",        RRI16,  0x58000000, 0xfc000000, JO },
    { "bne",        RRI16,  0x5c000000, 0xfc000000, JO },
    { "bgt",        RRI16,  0x60000000, 0xfc000000, JO },
    { "ble.2",      RRI16,  0x64000000, 0xfc000000, JO },
    { "bgt.2",      RRI16,  0x68000000, 0xfc000000, JO },
    { "ble",        RRI16,  0x6c000000, 0xfc000000, JO },

    /* sentinel & ultimate fallback */
    { NULL,         UNK,    0x00000000, 0x00000000 }
};
#undef UNK
#undef RR
#undef RRR
#undef FFFF
#undef RRI6
#undef RRI8
#undef RRI12
#undef RRI6I6
#undef RRI14
#undef RRI16
#undef AUI20
#undef RI21
#undef I25
#undef HEX
#undef JO
#undef M32
#undef SHL2
#undef FD
#undef FJ
#undef FK
#undef FDJK
#undef LS

static int32_t simm_from_uimm(uint32_t uimm, uint8_t width) {
    uint32_t a = 1 << width;
    uint32_t b = a >> 1;

    if (uimm < b) {
        return (int32_t)uimm;
    } else {
        return -((int32_t)(a - uimm));
    }
}

/**
 * Try to match one insn against list of known insns.
 *
 * Returns zero on failure, number of eaten bytes on success.
 */
static int match_insn(la_insn_t insn_word, struct la_op *out) {
    /* O(n) match */
    const struct la_disasm_matcher *ptr = loongarch_disasm_data;
    while (ptr->mnemonic != NULL) {
        la_insn_t masked_insn = insn_word & ptr->mask;
        if (masked_insn != ptr->match) {
            /* not this insn */
            ptr++;
            continue;
        }

        /* fill in output */
        out->mnemonic = ptr->mnemonic;
        out->fmt = ptr->fmt;
        out->render_flags = ptr->render_flags;
        switch (ptr->fmt) {
        case LA_INSN_FORMAT_UNKNOWN:
            out->insn.unknown = insn_word;
            break;

#define OPC(x)  ((x) >> 26)
#define RD(x)   ((x) & 0x1fU)
#define RJ(x)   (((x) >> 5) & 0x1fU)
#define RK(x)   (((x) >> 10) & 0x1fU)
#define RA(x)   (((x) >> 15) & 0x1fU)

#define SEL_RR(x)       (((x) >> 10) & 0xffffU)
#define SEL_RRR(x)      (((x) >> 15) & 0x7ffU)
#define SEL_FFFF(x)     (((x) >> 20) & 0x3fU)
#define SEL_RRI6(x)     (((x) >> 16) & 0x3ffU)
#define SEL_RRI8(x)     (((x) >> 18) & 0xffU)
#define SEL_RRI12(x)    (((x) >> 22) & 0xfU)
#define SEL_RRI6I6(x)   SEL_RRI12(x)
#define SEL_RRI14(x)    (((x) >> 24) & 0x3U)
#define SEL_AUI20(x)    (((x) >> 25) & 0x1U)
#define SEL_I25(x)      (((x) >> 9) & 0x1U)

#define IMM_RRI6(x)     (((x) >> 10) & 0x3fU)
#define IMM_RRI8(x)     (((x) >> 10) & 0xffU)
#define IMM_RRI12(x)    (((x) >> 10) & 0xfffU)
#define IMM_RRI6I6_1(x) IMM_RRI6(x)
#define IMM_RRI6I6_2(x) (IMM_RRI12(x) >> 6)
#define IMM_RRI14(x)    (((x) >> 10) & 0x3fffU)
#define IMM_RRI16(x)    (((x) >> 10) & 0xffffU)
#define IMM_AUI20(x)    (((x) >> 5) & 0xfffffU)
#define IMM_RI21(x)     ((((x) & 0x1f) << 16) | IMM_RRI16(x))
#define IMM_I25(x)      ((((x) & 0x1ff) << 16) | IMM_RRI16(x))

        case LA_INSN_FORMAT_RR:
            out->insn.rr.opcode = OPC(insn_word);
            out->insn.rr.sel = SEL_RR(insn_word);
            out->insn.rr.rd = RD(insn_word);
            out->insn.rr.rj = RJ(insn_word);
            break;

        case LA_INSN_FORMAT_RRR:
            out->insn.rrr.opcode = OPC(insn_word);
            out->insn.rrr.sel = SEL_RRR(insn_word);
            out->insn.rrr.rd = RD(insn_word);
            out->insn.rrr.rj = RJ(insn_word);
            out->insn.rrr.rk = RK(insn_word);
            break;

        case LA_INSN_FORMAT_FFFF:
            out->insn.ffff.opcode = OPC(insn_word);
            out->insn.ffff.sel = SEL_FFFF(insn_word);
            out->insn.ffff.rd = RD(insn_word);
            out->insn.ffff.rj = RJ(insn_word);
            out->insn.ffff.rk = RK(insn_word);
            out->insn.ffff.ra = RA(insn_word);
            break;

        case LA_INSN_FORMAT_RRI6:
            out->insn.rri6.opcode = OPC(insn_word);
            out->insn.rri6.sel = SEL_RRI6(insn_word);
            out->insn.rri6.rd = RD(insn_word);
            out->insn.rri6.rj = RJ(insn_word);
            out->insn.rri6.imm = IMM_RRI6(insn_word);
            break;

        case LA_INSN_FORMAT_RRI8:
            out->insn.rri8.opcode = OPC(insn_word);
            out->insn.rri8.sel = SEL_RRI8(insn_word);
            out->insn.rri8.rd = RD(insn_word);
            out->insn.rri8.rj = RJ(insn_word);
            out->insn.rri8.imm = IMM_RRI8(insn_word);
            break;

        case LA_INSN_FORMAT_RRI12:
            out->insn.rri12.opcode = OPC(insn_word);
            out->insn.rri12.sel = SEL_RRI12(insn_word);
            out->insn.rri12.rd = RD(insn_word);
            out->insn.rri12.rj = RJ(insn_word);
            out->insn.rri12.imm = IMM_RRI12(insn_word);
            break;

        case LA_INSN_FORMAT_RRI6I6:
            out->insn.rri6i6.opcode = OPC(insn_word);
            out->insn.rri6i6.sel = SEL_RRI6I6(insn_word);
            out->insn.rri6i6.rd = RD(insn_word);
            out->insn.rri6i6.rj = RJ(insn_word);
            out->insn.rri6i6.imm1 = IMM_RRI6I6_1(insn_word);
            out->insn.rri6i6.imm2 = IMM_RRI6I6_2(insn_word);
            break;

        case LA_INSN_FORMAT_RRI14:
            out->insn.rri14.opcode = OPC(insn_word);
            out->insn.rri14.sel = SEL_RRI14(insn_word);
            out->insn.rri14.rd = RD(insn_word);
            out->insn.rri14.rj = RJ(insn_word);
            out->insn.rri14.imm = IMM_RRI14(insn_word);
            break;

        case LA_INSN_FORMAT_RRI16:
            out->insn.rri16.opcode = OPC(insn_word);
            out->insn.rri16.rd = RD(insn_word);
            out->insn.rri16.rj = RJ(insn_word);
            out->insn.rri16.imm = IMM_RRI16(insn_word);
            break;

        case LA_INSN_FORMAT_AUI20:
            out->insn.aui20.opcode = OPC(insn_word);
            out->insn.aui20.sel = SEL_AUI20(insn_word);
            out->insn.aui20.rd = RD(insn_word);
            out->insn.aui20.imm = IMM_AUI20(insn_word);
            break;

        case LA_INSN_FORMAT_RI21:
            out->insn.ri21.opcode = OPC(insn_word);
            out->insn.ri21.rj = RJ(insn_word);
            out->insn.ri21.imm = IMM_RI21(insn_word);
            break;

        case LA_INSN_FORMAT_I25:
            out->insn.i25.opcode = OPC(insn_word);
            out->insn.i25.sel = SEL_I25(insn_word);
            out->insn.i25.imm = IMM_I25(insn_word);
            break;

#undef OPC
#undef RD
#undef RJ
#undef RK
#undef RA
#undef SEL_RR
#undef SEL_RRR
#undef SEL_FFFF
#undef SEL_RRI6
#undef SEL_RRI8
#undef SEL_RRI12
#undef SEL_RRI6I6
#undef SEL_RRI14
#undef SEL_AUI20
#undef SEL_I25
#undef IMM_RRI6
#undef IMM_RRI8
#undef IMM_RRI12
#undef IMM_RRI6I6_1
#undef IMM_RRI6I6_2
#undef IMM_RRI14
#undef IMM_RRI16
#undef IMM_AUI20
#undef IMM_RI21
#undef IMM_I25

        default:
            /* should never happen */
            return 0;
        }

        /* indicate success */
        return 4;
    }

    /* all matches missed, should never happen either but leave this around anyway */
    return 0;
}

static int print_insn(char *buf, int buflen, struct la_op *op, uint64_t pc) {
    bool print_hex = (op->render_flags & RENDER_FLAG_PRINT_IMM_HEX) != 0;
    bool imm_is_jump_offset = (op->render_flags & RENDER_FLAG_IMM_JUMP_OFFSET) != 0;
    bool is_load_store = (op->render_flags & RENDER_FLAG_LOAD_STORE) != 0;

    uint32_t imm;
    uint32_t imm1, imm2;
    int32_t simm;
    uint64_t jump_target;
    switch (op->fmt) {
    case LA_INSN_FORMAT_UNKNOWN:
        return snprintf(buf, buflen, "??? %08x", op->insn.unknown);

#define GPR(x)          loongarch_reg_names_gpr[x]
#define FPR(x)          loongarch_reg_names_fpr[x]
#define PRINT_RD(x)     ((op->render_flags & RENDER_FLAG_RD_IS_FPR) ? FPR(x) : GPR(x))
#define PRINT_RJ(x)     ((op->render_flags & RENDER_FLAG_RJ_IS_FPR) ? FPR(x) : GPR(x))
#define PRINT_RK(x)     ((op->render_flags & RENDER_FLAG_RK_IS_FPR) ? FPR(x) : GPR(x))
    case LA_INSN_FORMAT_RR:
        return snprintf(
            buf,
            buflen,
            "%s %s, %s",
            op->mnemonic,
            PRINT_RD(op->insn.rr.rd),
            PRINT_RJ(op->insn.rr.rj)
        );
    case LA_INSN_FORMAT_RRR:
        return snprintf(
            buf,
            buflen,
            "%s %s, %s, %s",
            op->mnemonic,
            PRINT_RD(op->insn.rrr.rd),
            PRINT_RJ(op->insn.rrr.rj),
            PRINT_RK(op->insn.rrr.rk)
        );
    case LA_INSN_FORMAT_FFFF:
        return snprintf(
            buf,
            buflen,
            "%s %s, %s, %s, %s",
            op->mnemonic,
            FPR(op->insn.ffff.rd),
            FPR(op->insn.ffff.rj),
            FPR(op->insn.ffff.rk),
            FPR(op->insn.ffff.ra)
        );
    case LA_INSN_FORMAT_RRI6:
        imm = op->insn.rri6.imm;
        if (op->render_flags & RENDER_FLAG_IMM_MINUS_32) {
            imm -= 32;
        }
        return snprintf(
            buf,
            buflen,
            "%s %s, %s, %d",
            op->mnemonic,
            PRINT_RD(op->insn.rri6.rd),
            PRINT_RJ(op->insn.rri6.rj),
            imm
        );
    case LA_INSN_FORMAT_RRI8:
        return snprintf(
            buf,
            buflen,
            print_hex ? "%s %s, %s, 0x%x" : "%s %s, %s, %d",
            op->mnemonic,
            PRINT_RD(op->insn.rri8.rd),
            PRINT_RJ(op->insn.rri8.rj),
            op->insn.rri8.imm
        );
    case LA_INSN_FORMAT_RRI12:
        imm = op->insn.rri12.imm;
        simm = simm_from_uimm(imm, 12);
        if (is_load_store) {
            return snprintf(
                buf,
                buflen,
                "%s %s, %d(%s)",
                op->mnemonic,
                PRINT_RD(op->insn.rri12.rd),
                simm,
                PRINT_RJ(op->insn.rri12.rj)
            );
        }
        return snprintf(
            buf,
            buflen,
            print_hex ? "%s %s, %s, 0x%x" : "%s %s, %s, %d",
            op->mnemonic,
            PRINT_RD(op->insn.rri12.rd),
            PRINT_RJ(op->insn.rri12.rj),
            print_hex ? imm : simm
        );
    case LA_INSN_FORMAT_RRI6I6:
        imm1 = op->insn.rri6i6.imm1;
        imm2 = op->insn.rri6i6.imm2;
        if (op->render_flags & RENDER_FLAG_IMM_MINUS_32) {
            imm1 -= 32;
            imm2 -= 32;
        }
        return snprintf(
            buf,
            buflen,
            "%s %s, %s, %d, %d",
            op->mnemonic,
            PRINT_RD(op->insn.rri6i6.rd),
            PRINT_RJ(op->insn.rri6i6.rj),
            imm1,
            imm2
        );
    case LA_INSN_FORMAT_RRI14:
        imm = op->insn.rri14.imm;
        simm = simm_from_uimm(imm, 14);
        if (op->render_flags & RENDER_FLAG_IMM_SHL_2) {
            imm <<= 2;
            simm <<= 2;
        }
        if (is_load_store) {
            return snprintf(
                buf,
                buflen,
                "%s %s, %d(%s)",
                op->mnemonic,
                PRINT_RD(op->insn.rri14.rd),
                simm,
                PRINT_RJ(op->insn.rri14.rj)
            );
        }
        return snprintf(
            buf,
            buflen,
            print_hex ? "%s %s, %s, 0x%x" : "%s %s, %s, %d",
            op->mnemonic,
            PRINT_RD(op->insn.rri14.rd),
            PRINT_RJ(op->insn.rri14.rj),
            print_hex ? imm : simm
        );
    case LA_INSN_FORMAT_RRI16:
        imm = op->insn.rri16.imm;
        if (imm_is_jump_offset) {
            simm = simm_from_uimm(imm, 16);
            jump_target = pc + simm * INSN_LENGTH_BYTES;
            return snprintf(
                buf,
                buflen,
                "%s %s, %s, 0x%lx",
                op->mnemonic,
                PRINT_RD(op->insn.rri16.rd),
                PRINT_RJ(op->insn.rri16.rj),
                jump_target
            );
        }
        return snprintf(
            buf,
            buflen,
            print_hex ? "%s %s, %s, 0x%x" : "%s %s, %s, %d",
            op->mnemonic,
            PRINT_RD(op->insn.rri16.rd),
            PRINT_RJ(op->insn.rri16.rj),
            imm
        );
    case LA_INSN_FORMAT_AUI20:
        return snprintf(
            buf,
            buflen,
            print_hex ? "%s %s, 0x%x" : "%s %s, %d",
            op->mnemonic,
            PRINT_RD(op->insn.aui20.rd),
            op->insn.aui20.imm
        );
    case LA_INSN_FORMAT_RI21:
        imm = op->insn.ri21.imm;
        if (imm_is_jump_offset) {
            simm = simm_from_uimm(imm, 21);
            jump_target = pc + simm * INSN_LENGTH_BYTES;
            return snprintf(
                buf,
                buflen,
                "%s %s, 0x%lx",
                op->mnemonic,
                PRINT_RJ(op->insn.ri21.rj),
                jump_target
            );
        }
        return snprintf(
            buf,
            buflen,
            "%s %s, %d",
            op->mnemonic,
            PRINT_RJ(op->insn.ri21.rj),
            imm
        );
    case LA_INSN_FORMAT_I25:
        imm = op->insn.i25.imm;
        if (imm_is_jump_offset) {
            simm = simm_from_uimm(imm, 25);
            jump_target = pc + simm * INSN_LENGTH_BYTES;
            return snprintf(
                buf,
                buflen,
                "%s 0x%lx",
                op->mnemonic,
                jump_target
            );
        }
        return snprintf(
            buf,
            buflen,
            "%s %d",
            op->mnemonic,
            imm
        );
#undef GPR
#undef FPR
#undef PRINT_RD
#undef PRINT_RJ
#undef PRINT_RK

    default:
        /* should never happen */
        return 0;
    }

    return 0;
}

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
    struct la_op matched_op = {};
    char insn_buf[64];  /* should be big enough */

    if (len < 4) return -1;

    /* read one little-endian insn word */
    la_insn_t insn_word = (
        buf[0]
        | (buf[1] << 8)
        | (buf[2] << 16)
        | (buf[3] << 24)
    );

    int ret = match_insn(insn_word, &matched_op);
    if (ret > 0) {
        print_insn(insn_buf, sizeof(insn_buf), &matched_op, a->pc);
        r_strbuf_set(&op->buf_asm, insn_buf);
    }
    return op->size = ret;
}

RAsmPlugin r_asm_plugin_loongarch = {
    .name = "loongarch",
    .license = "GPL3",
    .desc = "LoongArch disassembly plugin",
    .arch = "loongarch",
    .bits = 64,
    .endian = R_SYS_ENDIAN_LITTLE,
    .disassemble = &disassemble
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
    .type = R_LIB_TYPE_ASM,
    .data = &r_asm_plugin_loongarch,
    .version = R2_VERSION
};
#endif
