/*
 * e9disasm_arm64.c
 * Lightweight AArch64 Disassembler Implementation
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

#include "e9disasm_arm64.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/*
 * Disassembler context
 */
struct E9A64Disasm {
    int dummy;  /* Placeholder for future state */
};

/*
 * Register names
 */
static const char *REG_NAMES_X[] = {
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
    "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
    "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
    "x24", "x25", "x26", "x27", "x28", "x29", "x30", "xzr", "sp"
};

static const char *REG_NAMES_W[] = {
    "w0", "w1", "w2", "w3", "w4", "w5", "w6", "w7",
    "w8", "w9", "w10", "w11", "w12", "w13", "w14", "w15",
    "w16", "w17", "w18", "w19", "w20", "w21", "w22", "w23",
    "w24", "w25", "w26", "w27", "w28", "w29", "w30", "wzr", "wsp"
};

static const char *COND_NAMES[] = {
    "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
    "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"
};

static const char *SHIFT_NAMES[] = { "lsl", "lsr", "asr", "ror" };

/*
 * Create disassembler
 */
E9A64Disasm *e9_a64_disasm_create(void)
{
    E9A64Disasm *ctx = calloc(1, sizeof(E9A64Disasm));
    return ctx;
}

/*
 * Free disassembler
 */
void e9_a64_disasm_free(E9A64Disasm *ctx)
{
    free(ctx);
}

/*
 * Get register name
 */
const char *e9_a64_reg_name(E9A64Reg reg)
{
    if (reg >= E9_A64_REG_X0 && reg <= E9_A64_REG_SP) {
        return REG_NAMES_X[reg - E9_A64_REG_X0];
    }
    if (reg >= E9_A64_REG_W0 && reg <= E9_A64_REG_WSP) {
        return REG_NAMES_W[reg - E9_A64_REG_W0];
    }
    return "???";
}

/*
 * Get condition code name
 */
const char *e9_a64_cond_name(E9A64Cond cond)
{
    if (cond <= E9_A64_COND_NV) {
        return COND_NAMES[cond];
    }
    return "??";
}

/*
 * Helper: Read 32-bit little-endian instruction
 */
static inline uint32_t read_insn(const uint8_t *p)
{
    return p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24);
}

/*
 * Helper: Sign-extend immediate
 */
static inline int64_t sign_extend(uint64_t val, int bits)
{
    int64_t sign_bit = 1LL << (bits - 1);
    return (int64_t)((val ^ sign_bit) - sign_bit);
}

/*
 * Extract bit field
 */
#define BITS(insn, hi, lo) (((insn) >> (lo)) & ((1 << ((hi) - (lo) + 1)) - 1))
#define BIT(insn, n) (((insn) >> (n)) & 1)

/*
 * Decode register with size selection
 */
static E9A64Reg decode_reg(uint32_t num, bool is_64bit, bool is_sp)
{
    if (num == 31) {
        if (is_sp) {
            return is_64bit ? E9_A64_REG_SP : E9_A64_REG_WSP;
        }
        return is_64bit ? E9_A64_REG_XZR : E9_A64_REG_WZR;
    }
    return is_64bit ? (E9A64Reg)(E9_A64_REG_X0 + num) :
                      (E9A64Reg)(E9_A64_REG_W0 + num);
}

/*
 * Disassemble single instruction
 */
int e9_a64_disasm_one(E9A64Disasm *ctx, const uint8_t *code, size_t size,
                      uint64_t address, E9A64Insn *insn)
{
    (void)ctx;

    if (!code || size < 4 || !insn) return 0;

    memset(insn, 0, sizeof(*insn));
    insn->address = address;
    insn->encoding = read_insn(code);

    uint32_t enc = insn->encoding;

    /* Extract top-level opcode fields */
    uint32_t op0 = BITS(enc, 31, 25);

    /* Data Processing -- Immediate */
    if ((op0 & 0x71) == 0x10) {
        /* PC-rel addressing (ADR/ADRP) */
        bool is_adrp = BIT(enc, 31);
        int64_t imm = (sign_extend(BITS(enc, 23, 5), 19) << 2) | BITS(enc, 30, 29);
        uint32_t rd = BITS(enc, 4, 0);

        strcpy(insn->mnemonic, is_adrp ? "adrp" : "adr");
        insn->category = E9_A64_CAT_DATA_PROC;
        insn->num_operands = 2;

        insn->operands[0].type = E9_A64_OP_REG;
        insn->operands[0].reg = decode_reg(rd, true, false);
        insn->operands[0].size = 8;

        insn->operands[1].type = E9_A64_OP_LABEL;
        if (is_adrp) {
            insn->operands[1].label = (address & ~0xFFFULL) + (imm << 12);
        } else {
            insn->operands[1].label = address + imm;
        }
    }
    /* Add/Sub immediate */
    else if ((op0 & 0x71) == 0x11) {
        bool is_64bit = BIT(enc, 31);
        bool is_sub = BIT(enc, 30);
        bool set_flags = BIT(enc, 29);
        uint32_t shift = BITS(enc, 23, 22);
        uint32_t imm12 = BITS(enc, 21, 10);
        uint32_t rn = BITS(enc, 9, 5);
        uint32_t rd = BITS(enc, 4, 0);

        if (is_sub && rd == 31 && set_flags) {
            strcpy(insn->mnemonic, "cmp");
            insn->category = E9_A64_CAT_COMPARE;
            insn->num_operands = 2;

            insn->operands[0].type = E9_A64_OP_REG;
            insn->operands[0].reg = decode_reg(rn, is_64bit, true);
            insn->operands[0].size = is_64bit ? 8 : 4;

            insn->operands[1].type = E9_A64_OP_IMM;
            insn->operands[1].imm = shift ? (imm12 << 12) : imm12;
        } else {
            snprintf(insn->mnemonic, sizeof(insn->mnemonic), "%s%s",
                     is_sub ? "sub" : "add", set_flags ? "s" : "");
            insn->category = E9_A64_CAT_DATA_PROC;
            insn->num_operands = 3;

            insn->operands[0].type = E9_A64_OP_REG;
            insn->operands[0].reg = decode_reg(rd, is_64bit, !set_flags);
            insn->operands[0].size = is_64bit ? 8 : 4;

            insn->operands[1].type = E9_A64_OP_REG;
            insn->operands[1].reg = decode_reg(rn, is_64bit, true);
            insn->operands[1].size = is_64bit ? 8 : 4;

            insn->operands[2].type = E9_A64_OP_IMM;
            insn->operands[2].imm = shift ? (imm12 << 12) : imm12;
        }
    }
    /* Move wide immediate */
    else if ((op0 & 0x71) == 0x12) {
        bool is_64bit = BIT(enc, 31);
        uint32_t opc = BITS(enc, 30, 29);
        uint32_t hw = BITS(enc, 22, 21);
        uint32_t imm16 = BITS(enc, 20, 5);
        uint32_t rd = BITS(enc, 4, 0);

        static const char *mov_ops[] = { "movn", "???", "movz", "movk" };
        strcpy(insn->mnemonic, mov_ops[opc]);
        insn->category = E9_A64_CAT_MOVE;
        insn->num_operands = 2;

        insn->operands[0].type = E9_A64_OP_REG;
        insn->operands[0].reg = decode_reg(rd, is_64bit, false);
        insn->operands[0].size = is_64bit ? 8 : 4;

        insn->operands[1].type = E9_A64_OP_IMM;
        insn->operands[1].imm = (uint64_t)imm16 << (hw * 16);
    }
    /* Logical immediate */
    else if ((op0 & 0x71) == 0x12 && BITS(enc, 25, 23) == 4) {
        /* Simplified - just show raw encoding */
        strcpy(insn->mnemonic, "logic_imm");
        insn->category = E9_A64_CAT_DATA_PROC;
    }
    /* Branches */
    else if ((op0 & 0x7C) == 0x14) {
        /* Unconditional branch (B, BL) */
        bool is_bl = BIT(enc, 31);
        int64_t imm26 = sign_extend(BITS(enc, 25, 0), 26) << 2;

        strcpy(insn->mnemonic, is_bl ? "bl" : "b");
        insn->category = E9_A64_CAT_BRANCH;
        insn->is_branch = true;
        insn->is_call = is_bl;
        insn->branch_target = address + imm26;
        insn->num_operands = 1;

        insn->operands[0].type = E9_A64_OP_LABEL;
        insn->operands[0].label = insn->branch_target;
    }
    /* Compare and branch */
    else if ((op0 & 0x7E) == 0x34) {
        bool is_64bit = BIT(enc, 31);
        bool is_nz = BIT(enc, 24);
        int64_t imm19 = sign_extend(BITS(enc, 23, 5), 19) << 2;
        uint32_t rt = BITS(enc, 4, 0);

        strcpy(insn->mnemonic, is_nz ? "cbnz" : "cbz");
        insn->category = E9_A64_CAT_BRANCH;
        insn->is_branch = true;
        insn->is_conditional = true;
        insn->branch_target = address + imm19;
        insn->num_operands = 2;

        insn->operands[0].type = E9_A64_OP_REG;
        insn->operands[0].reg = decode_reg(rt, is_64bit, false);
        insn->operands[0].size = is_64bit ? 8 : 4;

        insn->operands[1].type = E9_A64_OP_LABEL;
        insn->operands[1].label = insn->branch_target;
    }
    /* Conditional branch */
    else if ((op0 & 0x7E) == 0x54) {
        int64_t imm19 = sign_extend(BITS(enc, 23, 5), 19) << 2;
        uint32_t cond = BITS(enc, 3, 0);

        snprintf(insn->mnemonic, sizeof(insn->mnemonic), "b.%s",
                 COND_NAMES[cond]);
        insn->category = E9_A64_CAT_BRANCH;
        insn->is_branch = true;
        insn->is_conditional = true;
        insn->branch_target = address + imm19;
        insn->num_operands = 1;

        insn->operands[0].type = E9_A64_OP_LABEL;
        insn->operands[0].label = insn->branch_target;
    }
    /* Test and branch */
    else if ((op0 & 0x7E) == 0x36) {
        bool is_64bit = BIT(enc, 31);
        bool is_nz = BIT(enc, 24);
        uint32_t b5 = BIT(enc, 31);
        uint32_t b40 = BITS(enc, 23, 19);
        int64_t imm14 = sign_extend(BITS(enc, 18, 5), 14) << 2;
        uint32_t rt = BITS(enc, 4, 0);

        strcpy(insn->mnemonic, is_nz ? "tbnz" : "tbz");
        insn->category = E9_A64_CAT_BRANCH;
        insn->is_branch = true;
        insn->is_conditional = true;
        insn->branch_target = address + imm14;
        insn->num_operands = 3;

        insn->operands[0].type = E9_A64_OP_REG;
        insn->operands[0].reg = decode_reg(rt, is_64bit, false);

        insn->operands[1].type = E9_A64_OP_IMM;
        insn->operands[1].imm = (b5 << 5) | b40;

        insn->operands[2].type = E9_A64_OP_LABEL;
        insn->operands[2].label = insn->branch_target;
    }
    /* Unconditional branch (register) */
    else if ((op0 & 0x7E) == 0x6A) {
        uint32_t opc = BITS(enc, 24, 21);
        uint32_t rn = BITS(enc, 9, 5);

        if (opc == 0) {
            strcpy(insn->mnemonic, "br");
            insn->is_branch = true;
        } else if (opc == 1) {
            strcpy(insn->mnemonic, "blr");
            insn->is_branch = true;
            insn->is_call = true;
        } else if (opc == 2) {
            strcpy(insn->mnemonic, "ret");
            insn->is_branch = true;
            insn->is_ret = true;
        } else {
            strcpy(insn->mnemonic, "br_reg");
        }

        insn->category = E9_A64_CAT_BRANCH;
        insn->num_operands = (opc == 2 && rn == 30) ? 0 : 1;

        if (insn->num_operands > 0) {
            insn->operands[0].type = E9_A64_OP_REG;
            insn->operands[0].reg = decode_reg(rn, true, false);
            insn->operands[0].size = 8;
        }
    }
    /* Load/Store */
    else if ((op0 & 0x0A) == 0x08) {
        uint32_t size = BITS(enc, 31, 30);
        bool is_vector = BIT(enc, 26);
        uint32_t opc = BITS(enc, 23, 22);

        if (BITS(enc, 29, 28) == 3 && BITS(enc, 25, 24) == 1) {
            /* Load/store register (unsigned immediate) */
            uint32_t imm12 = BITS(enc, 21, 10);
            uint32_t rn = BITS(enc, 9, 5);
            uint32_t rt = BITS(enc, 4, 0);
            bool is_load = BIT(enc, 22);

            int scale = size;
            int64_t offset = imm12 << scale;

            strcpy(insn->mnemonic, is_load ? "ldr" : "str");
            insn->category = E9_A64_CAT_LOAD_STORE;
            insn->reads_memory = is_load;
            insn->writes_memory = !is_load;
            insn->num_operands = 2;

            insn->operands[0].type = E9_A64_OP_REG;
            insn->operands[0].reg = decode_reg(rt, size == 3, false);
            insn->operands[0].size = 1 << size;

            insn->operands[1].type = E9_A64_OP_MEM;
            insn->operands[1].mem.base = decode_reg(rn, true, true);
            insn->operands[1].mem.offset = offset;
            insn->operands[1].size = 1 << size;
        }
        /* Load/store register pair */
        else if (BITS(enc, 29, 27) == 5) {
            uint32_t opc2 = BITS(enc, 23, 22);
            bool is_load = BIT(enc, 22);
            int64_t imm7 = sign_extend(BITS(enc, 21, 15), 7);
            uint32_t rt2 = BITS(enc, 14, 10);
            uint32_t rn = BITS(enc, 9, 5);
            uint32_t rt = BITS(enc, 4, 0);
            bool is_64bit = BIT(enc, 31);

            int scale = 2 + (is_64bit ? 1 : 0);
            int64_t offset = imm7 << scale;

            strcpy(insn->mnemonic, is_load ? "ldp" : "stp");
            insn->category = E9_A64_CAT_LOAD_STORE;
            insn->reads_memory = is_load;
            insn->writes_memory = !is_load;
            insn->num_operands = 3;

            insn->operands[0].type = E9_A64_OP_REG;
            insn->operands[0].reg = decode_reg(rt, is_64bit, false);
            insn->operands[0].size = is_64bit ? 8 : 4;

            insn->operands[1].type = E9_A64_OP_REG;
            insn->operands[1].reg = decode_reg(rt2, is_64bit, false);
            insn->operands[1].size = is_64bit ? 8 : 4;

            insn->operands[2].type = E9_A64_OP_MEM;
            insn->operands[2].mem.base = decode_reg(rn, true, true);
            insn->operands[2].mem.offset = offset;
        }
        else {
            strcpy(insn->mnemonic, "ldst");
            insn->category = E9_A64_CAT_LOAD_STORE;
        }

        (void)is_vector;
        (void)opc;
    }
    /* Data Processing -- Register */
    else if ((op0 & 0x0F) == 0x0A || (op0 & 0x0F) == 0x0B) {
        bool is_64bit = BIT(enc, 31);
        uint32_t opc = BITS(enc, 30, 29);
        bool set_flags = BIT(enc, 29);
        uint32_t shift = BITS(enc, 23, 22);
        bool is_neg = BIT(enc, 21);
        uint32_t rm = BITS(enc, 20, 16);
        uint32_t imm6 = BITS(enc, 15, 10);
        uint32_t rn = BITS(enc, 9, 5);
        uint32_t rd = BITS(enc, 4, 0);

        /* Logical shifted register */
        if ((BITS(enc, 28, 24) & 0x1E) == 0x0A) {
            static const char *log_ops[] = { "and", "orr", "eor", "ands" };
            static const char *log_neg[] = { "bic", "orn", "eon", "bics" };
            strcpy(insn->mnemonic, is_neg ? log_neg[opc] : log_ops[opc]);

            /* MOV alias */
            if (opc == 1 && !is_neg && rn == 31 && imm6 == 0 && shift == 0) {
                strcpy(insn->mnemonic, "mov");
                insn->category = E9_A64_CAT_MOVE;
                insn->num_operands = 2;

                insn->operands[0].type = E9_A64_OP_REG;
                insn->operands[0].reg = decode_reg(rd, is_64bit, false);
                insn->operands[0].size = is_64bit ? 8 : 4;

                insn->operands[1].type = E9_A64_OP_REG;
                insn->operands[1].reg = decode_reg(rm, is_64bit, false);
                insn->operands[1].size = is_64bit ? 8 : 4;
            } else {
                insn->category = E9_A64_CAT_DATA_PROC;
                insn->num_operands = 3;

                insn->operands[0].type = E9_A64_OP_REG;
                insn->operands[0].reg = decode_reg(rd, is_64bit, false);

                insn->operands[1].type = E9_A64_OP_REG;
                insn->operands[1].reg = decode_reg(rn, is_64bit, false);

                insn->operands[2].type = E9_A64_OP_SHIFT;
                insn->operands[2].shifted.reg = decode_reg(rm, is_64bit, false);
                insn->operands[2].shifted.shift = (E9A64Shift)shift;
                insn->operands[2].shifted.amount = imm6;
            }
        }
        /* Add/sub shifted register */
        else if ((BITS(enc, 28, 24) & 0x1E) == 0x0B) {
            bool is_sub = BIT(enc, 30);

            /* CMP alias */
            if (is_sub && rd == 31 && set_flags) {
                strcpy(insn->mnemonic, "cmp");
                insn->category = E9_A64_CAT_COMPARE;
                insn->num_operands = 2;

                insn->operands[0].type = E9_A64_OP_REG;
                insn->operands[0].reg = decode_reg(rn, is_64bit, true);

                insn->operands[1].type = E9_A64_OP_REG;
                insn->operands[1].reg = decode_reg(rm, is_64bit, false);
            } else {
                snprintf(insn->mnemonic, sizeof(insn->mnemonic), "%s%s",
                         is_sub ? "sub" : "add", set_flags ? "s" : "");
                insn->category = E9_A64_CAT_DATA_PROC;
                insn->num_operands = 3;

                insn->operands[0].type = E9_A64_OP_REG;
                insn->operands[0].reg = decode_reg(rd, is_64bit, !set_flags);

                insn->operands[1].type = E9_A64_OP_REG;
                insn->operands[1].reg = decode_reg(rn, is_64bit, true);

                if (imm6 != 0) {
                    insn->operands[2].type = E9_A64_OP_SHIFT;
                    insn->operands[2].shifted.reg = decode_reg(rm, is_64bit, false);
                    insn->operands[2].shifted.shift = (E9A64Shift)shift;
                    insn->operands[2].shifted.amount = imm6;
                } else {
                    insn->operands[2].type = E9_A64_OP_REG;
                    insn->operands[2].reg = decode_reg(rm, is_64bit, false);
                }
            }
        }
        else {
            strcpy(insn->mnemonic, "data_reg");
            insn->category = E9_A64_CAT_DATA_PROC;
        }
    }
    /* System instructions */
    else if ((enc & 0xFFC00000) == 0xD5000000) {
        uint32_t l = BIT(enc, 21);
        uint32_t op0_sys = BITS(enc, 20, 19);
        uint32_t op1 = BITS(enc, 18, 16);
        uint32_t crn = BITS(enc, 15, 12);
        uint32_t crm = BITS(enc, 11, 8);
        uint32_t op2 = BITS(enc, 7, 5);
        uint32_t rt = BITS(enc, 4, 0);

        if (op0_sys == 1 && l == 0 && rt == 31) {
            /* Hint instructions */
            if (crn == 2 && op1 == 3) {
                switch ((crm << 3) | op2) {
                    case 0: strcpy(insn->mnemonic, "nop"); break;
                    case 1: strcpy(insn->mnemonic, "yield"); break;
                    case 2: strcpy(insn->mnemonic, "wfe"); break;
                    case 3: strcpy(insn->mnemonic, "wfi"); break;
                    case 4: strcpy(insn->mnemonic, "sev"); break;
                    case 5: strcpy(insn->mnemonic, "sevl"); break;
                    default: strcpy(insn->mnemonic, "hint"); break;
                }
                insn->category = E9_A64_CAT_SYSTEM;
            }
            /* Barriers */
            else if (crn == 3) {
                switch (op2) {
                    case 2: strcpy(insn->mnemonic, "clrex"); break;
                    case 4: strcpy(insn->mnemonic, "dsb"); break;
                    case 5: strcpy(insn->mnemonic, "dmb"); break;
                    case 6: strcpy(insn->mnemonic, "isb"); break;
                    default: strcpy(insn->mnemonic, "barrier"); break;
                }
                insn->category = E9_A64_CAT_SYSTEM;
            }
            else {
                strcpy(insn->mnemonic, "sys");
                insn->category = E9_A64_CAT_SYSTEM;
            }
        }
        /* MSR/MRS */
        else if (op0_sys >= 2) {
            strcpy(insn->mnemonic, l ? "mrs" : "msr");
            insn->category = E9_A64_CAT_SYSTEM;
            insn->num_operands = 2;

            insn->operands[l ? 0 : 1].type = E9_A64_OP_REG;
            insn->operands[l ? 0 : 1].reg = decode_reg(rt, true, false);

            insn->operands[l ? 1 : 0].type = E9_A64_OP_SYSREG;
        }
        else {
            strcpy(insn->mnemonic, "sys");
            insn->category = E9_A64_CAT_SYSTEM;
        }
    }
    /* Exception generation */
    else if ((enc & 0xFF000000) == 0xD4000000) {
        uint32_t opc = BITS(enc, 23, 21);
        uint32_t imm16 = BITS(enc, 20, 5);
        uint32_t ll = BITS(enc, 1, 0);

        switch ((opc << 2) | ll) {
            case 0x01: strcpy(insn->mnemonic, "svc"); break;
            case 0x02: strcpy(insn->mnemonic, "hvc"); break;
            case 0x03: strcpy(insn->mnemonic, "smc"); break;
            case 0x04: strcpy(insn->mnemonic, "brk"); break;
            case 0x08: strcpy(insn->mnemonic, "hlt"); break;
            default: strcpy(insn->mnemonic, "exc"); break;
        }
        insn->category = E9_A64_CAT_EXCEPTION;
        insn->num_operands = 1;
        insn->operands[0].type = E9_A64_OP_IMM;
        insn->operands[0].imm = imm16;
    }
    /* Default: unknown */
    else {
        snprintf(insn->mnemonic, sizeof(insn->mnemonic), ".inst 0x%08x", enc);
        insn->category = E9_A64_CAT_INVALID;
    }

    /* Format text output */
    e9_a64_insn_format(insn, insn->text, sizeof(insn->text));

    return 4;
}

/*
 * Format instruction to string
 */
void e9_a64_insn_format(const E9A64Insn *insn, char *buf, size_t size)
{
    if (!insn || !buf || size == 0) return;

    char *p = buf;
    char *end = buf + size - 1;

    /* Mnemonic */
    p += snprintf(p, end - p, "%s", insn->mnemonic);

    /* Operands */
    for (int i = 0; i < insn->num_operands && p < end; i++) {
        p += snprintf(p, end - p, "%s", (i == 0) ? " " : ", ");

        const E9A64Operand *op = &insn->operands[i];
        switch (op->type) {
            case E9_A64_OP_REG:
                p += snprintf(p, end - p, "%s", e9_a64_reg_name(op->reg));
                break;

            case E9_A64_OP_IMM:
                if (op->imm < 0) {
                    p += snprintf(p, end - p, "#-0x%llx",
                                  (unsigned long long)-op->imm);
                } else {
                    p += snprintf(p, end - p, "#0x%llx",
                                  (unsigned long long)op->imm);
                }
                break;

            case E9_A64_OP_LABEL:
                p += snprintf(p, end - p, "0x%llx",
                              (unsigned long long)op->label);
                break;

            case E9_A64_OP_MEM:
                p += snprintf(p, end - p, "[%s",
                              e9_a64_reg_name(op->mem.base));
                if (op->mem.offset != 0) {
                    if (op->mem.offset > 0) {
                        p += snprintf(p, end - p, ", #0x%llx",
                                      (unsigned long long)op->mem.offset);
                    } else {
                        p += snprintf(p, end - p, ", #-0x%llx",
                                      (unsigned long long)-op->mem.offset);
                    }
                }
                p += snprintf(p, end - p, "]");
                if (op->mem.post_index) {
                    p += snprintf(p, end - p, "!");
                }
                break;

            case E9_A64_OP_SHIFT:
                p += snprintf(p, end - p, "%s",
                              e9_a64_reg_name(op->shifted.reg));
                if (op->shifted.amount > 0) {
                    p += snprintf(p, end - p, ", %s #%d",
                                  SHIFT_NAMES[op->shifted.shift],
                                  op->shifted.amount);
                }
                break;

            case E9_A64_OP_COND:
                p += snprintf(p, end - p, "%s", COND_NAMES[op->cond]);
                break;

            case E9_A64_OP_SYSREG:
                p += snprintf(p, end - p, "<sysreg>");
                break;

            default:
                break;
        }
    }

    *p = '\0';
}

/*
 * Disassemble multiple instructions
 */
size_t e9_a64_disasm(E9A64Disasm *ctx, const uint8_t *code, size_t size,
                     uint64_t address, size_t count, E9A64Insn **insns)
{
    if (!ctx || !code || size < 4 || !insns) return 0;

    *insns = calloc(count, sizeof(E9A64Insn));
    if (!*insns) return 0;

    size_t decoded = 0;
    size_t offset = 0;

    while (decoded < count && offset + 4 <= size) {
        int len = e9_a64_disasm_one(ctx, code + offset, size - offset,
                                     address + offset, &(*insns)[decoded]);
        if (len != 4) break;

        offset += 4;
        decoded++;
    }

    return decoded;
}

/*
 * Free instruction array
 */
void e9_a64_insns_free(E9A64Insn *insns, size_t count)
{
    (void)count;
    free(insns);
}

/*
 * Check for function prologue
 */
bool e9_a64_is_prologue(const uint8_t *code, size_t size)
{
    if (size < 4) return false;

    uint32_t insn = read_insn(code);

    /* STP x29, x30, [sp, #-...] - common prologue */
    if ((insn & 0xFFC003E0) == 0xA9807BFD) {
        return true;
    }

    /* SUB sp, sp, #... - stack allocation */
    if ((insn & 0xFF0003FF) == 0xD10003FF) {
        return true;
    }

    /* PACIASP / PACIBSP (PAC prologue) */
    if (insn == 0xD503233F || insn == 0xD503237F) {
        return true;
    }

    return false;
}

/*
 * Check for function epilogue
 */
bool e9_a64_is_epilogue(const uint8_t *code, size_t size)
{
    if (size < 4) return false;

    uint32_t insn = read_insn(code);

    /* RET */
    if ((insn & 0xFFFFFC1F) == 0xD65F0000) {
        return true;
    }

    /* RET with PAC (RETAA/RETAB) */
    if (insn == 0xD65F0BFF || insn == 0xD65F0FFF) {
        return true;
    }

    return false;
}
