/*
 * e9disasm_x86.c
 * Lightweight x86-64 Disassembler Implementation
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

#include "e9disasm_x86.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/*
 * Disassembler context
 */
struct E9X86Disasm {
    int mode;  /* 16, 32, or 64 */
};

/*
 * Register names
 */
static const char *REG_NAMES[] = {
    [E9_X86_REG_NONE] = "",

    /* 64-bit */
    [E9_X86_REG_RAX] = "rax", [E9_X86_REG_RCX] = "rcx",
    [E9_X86_REG_RDX] = "rdx", [E9_X86_REG_RBX] = "rbx",
    [E9_X86_REG_RSP] = "rsp", [E9_X86_REG_RBP] = "rbp",
    [E9_X86_REG_RSI] = "rsi", [E9_X86_REG_RDI] = "rdi",
    [E9_X86_REG_R8]  = "r8",  [E9_X86_REG_R9]  = "r9",
    [E9_X86_REG_R10] = "r10", [E9_X86_REG_R11] = "r11",
    [E9_X86_REG_R12] = "r12", [E9_X86_REG_R13] = "r13",
    [E9_X86_REG_R14] = "r14", [E9_X86_REG_R15] = "r15",
    [E9_X86_REG_RIP] = "rip",

    /* 32-bit */
    [E9_X86_REG_EAX] = "eax", [E9_X86_REG_ECX] = "ecx",
    [E9_X86_REG_EDX] = "edx", [E9_X86_REG_EBX] = "ebx",
    [E9_X86_REG_ESP] = "esp", [E9_X86_REG_EBP] = "ebp",
    [E9_X86_REG_ESI] = "esi", [E9_X86_REG_EDI] = "edi",
    [E9_X86_REG_R8D] = "r8d", [E9_X86_REG_R9D] = "r9d",
    [E9_X86_REG_R10D] = "r10d", [E9_X86_REG_R11D] = "r11d",
    [E9_X86_REG_R12D] = "r12d", [E9_X86_REG_R13D] = "r13d",
    [E9_X86_REG_R14D] = "r14d", [E9_X86_REG_R15D] = "r15d",
    [E9_X86_REG_EIP] = "eip",

    /* 16-bit */
    [E9_X86_REG_AX] = "ax", [E9_X86_REG_CX] = "cx",
    [E9_X86_REG_DX] = "dx", [E9_X86_REG_BX] = "bx",
    [E9_X86_REG_SP] = "sp", [E9_X86_REG_BP] = "bp",
    [E9_X86_REG_SI] = "si", [E9_X86_REG_DI] = "di",

    /* 8-bit */
    [E9_X86_REG_AL] = "al", [E9_X86_REG_CL] = "cl",
    [E9_X86_REG_DL] = "dl", [E9_X86_REG_BL] = "bl",
    [E9_X86_REG_AH] = "ah", [E9_X86_REG_CH] = "ch",
    [E9_X86_REG_DH] = "dh", [E9_X86_REG_BH] = "bh",
    [E9_X86_REG_SPL] = "spl", [E9_X86_REG_BPL] = "bpl",
    [E9_X86_REG_SIL] = "sil", [E9_X86_REG_DIL] = "dil",

    /* Segment */
    [E9_X86_REG_CS] = "cs", [E9_X86_REG_DS] = "ds",
    [E9_X86_REG_ES] = "es", [E9_X86_REG_FS] = "fs",
    [E9_X86_REG_GS] = "gs", [E9_X86_REG_SS] = "ss",

    /* XMM */
    [E9_X86_REG_XMM0] = "xmm0", [E9_X86_REG_XMM1] = "xmm1",
    [E9_X86_REG_XMM2] = "xmm2", [E9_X86_REG_XMM3] = "xmm3",
    [E9_X86_REG_XMM4] = "xmm4", [E9_X86_REG_XMM5] = "xmm5",
    [E9_X86_REG_XMM6] = "xmm6", [E9_X86_REG_XMM7] = "xmm7",
    [E9_X86_REG_XMM8] = "xmm8", [E9_X86_REG_XMM9] = "xmm9",
    [E9_X86_REG_XMM10] = "xmm10", [E9_X86_REG_XMM11] = "xmm11",
    [E9_X86_REG_XMM12] = "xmm12", [E9_X86_REG_XMM13] = "xmm13",
    [E9_X86_REG_XMM14] = "xmm14", [E9_X86_REG_XMM15] = "xmm15",
};

/* Register tables for ModR/M decoding */
static const E9X86Reg REG64[] = {
    E9_X86_REG_RAX, E9_X86_REG_RCX, E9_X86_REG_RDX, E9_X86_REG_RBX,
    E9_X86_REG_RSP, E9_X86_REG_RBP, E9_X86_REG_RSI, E9_X86_REG_RDI,
    E9_X86_REG_R8,  E9_X86_REG_R9,  E9_X86_REG_R10, E9_X86_REG_R11,
    E9_X86_REG_R12, E9_X86_REG_R13, E9_X86_REG_R14, E9_X86_REG_R15,
};

static const E9X86Reg REG32[] = {
    E9_X86_REG_EAX, E9_X86_REG_ECX, E9_X86_REG_EDX, E9_X86_REG_EBX,
    E9_X86_REG_ESP, E9_X86_REG_EBP, E9_X86_REG_ESI, E9_X86_REG_EDI,
    E9_X86_REG_R8D, E9_X86_REG_R9D, E9_X86_REG_R10D, E9_X86_REG_R11D,
    E9_X86_REG_R12D, E9_X86_REG_R13D, E9_X86_REG_R14D, E9_X86_REG_R15D,
};

static const E9X86Reg REG8[] = {
    E9_X86_REG_AL, E9_X86_REG_CL, E9_X86_REG_DL, E9_X86_REG_BL,
    E9_X86_REG_AH, E9_X86_REG_CH, E9_X86_REG_DH, E9_X86_REG_BH,
};

static const E9X86Reg REG8_REX[] = {
    E9_X86_REG_AL, E9_X86_REG_CL, E9_X86_REG_DL, E9_X86_REG_BL,
    E9_X86_REG_SPL, E9_X86_REG_BPL, E9_X86_REG_SIL, E9_X86_REG_DIL,
};

/*
 * Create disassembler
 */
E9X86Disasm *e9_x86_disasm_create(int mode)
{
    if (mode != 16 && mode != 32 && mode != 64) {
        return NULL;
    }

    E9X86Disasm *ctx = calloc(1, sizeof(E9X86Disasm));
    if (!ctx) return NULL;

    ctx->mode = mode;
    return ctx;
}

/*
 * Free disassembler
 */
void e9_x86_disasm_free(E9X86Disasm *ctx)
{
    free(ctx);
}

/*
 * Get register name
 */
const char *e9_x86_reg_name(E9X86Reg reg)
{
    if (reg >= sizeof(REG_NAMES) / sizeof(REG_NAMES[0])) {
        return "???";
    }
    return REG_NAMES[reg];
}

/*
 * Get register size
 */
int e9_x86_reg_size(E9X86Reg reg)
{
    if (reg >= E9_X86_REG_RAX && reg <= E9_X86_REG_RIP) return 8;
    if (reg >= E9_X86_REG_EAX && reg <= E9_X86_REG_EIP) return 4;
    if (reg >= E9_X86_REG_AX && reg <= E9_X86_REG_DI) return 2;
    if (reg >= E9_X86_REG_AL && reg <= E9_X86_REG_DIL) return 1;
    if (reg >= E9_X86_REG_XMM0 && reg <= E9_X86_REG_XMM15) return 16;
    return 0;
}

/*
 * Helper: Read little-endian values
 */
static inline int8_t read_i8(const uint8_t *p) { return (int8_t)p[0]; }
static inline int16_t read_i16(const uint8_t *p) {
    return (int16_t)(p[0] | (p[1] << 8));
}
static inline int32_t read_i32(const uint8_t *p) {
    return (int32_t)(p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24));
}
static inline int64_t read_i64(const uint8_t *p) {
    return (int64_t)read_i32(p) | ((int64_t)read_i32(p + 4) << 32);
}

/*
 * Decode ModR/M byte
 */
static int decode_modrm(E9X86Disasm *ctx, const uint8_t *code, size_t size,
                        int pos, uint8_t rex, int op_size,
                        E9X86Operand *reg_op, E9X86Operand *rm_op)
{
    if (pos >= (int)size) return -1;

    uint8_t modrm = code[pos++];
    uint8_t mod = (modrm >> 6) & 0x3;
    uint8_t reg = (modrm >> 3) & 0x7;
    uint8_t rm = modrm & 0x7;

    /* REX extensions */
    if (rex & 0x04) reg |= 8;  /* REX.R */
    if (rex & 0x01) rm |= 8;   /* REX.B */

    /* Register operand from reg field */
    if (reg_op) {
        reg_op->type = E9_X86_OP_REG;
        reg_op->size = op_size;
        if (op_size == 8) {
            reg_op->reg = REG64[reg];
        } else if (op_size == 4) {
            reg_op->reg = REG32[reg];
        } else if (op_size == 1) {
            reg_op->reg = (rex) ? REG8_REX[reg & 7] : REG8[reg & 7];
        }
    }

    /* R/M operand */
    if (!rm_op) return pos;

    if (mod == 3) {
        /* Register direct */
        rm_op->type = E9_X86_OP_REG;
        rm_op->size = op_size;
        if (op_size == 8) {
            rm_op->reg = REG64[rm];
        } else if (op_size == 4) {
            rm_op->reg = REG32[rm];
        } else if (op_size == 1) {
            rm_op->reg = (rex) ? REG8_REX[rm & 7] : REG8[rm & 7];
        }
    } else {
        /* Memory operand */
        rm_op->type = E9_X86_OP_MEM;
        rm_op->size = op_size;
        rm_op->mem.base = E9_X86_REG_NONE;
        rm_op->mem.index = E9_X86_REG_NONE;
        rm_op->mem.scale = 1;
        rm_op->mem.disp = 0;
        rm_op->mem.segment = E9_X86_REG_NONE;

        bool has_sib = (ctx->mode >= 32) && (rm & 7) == 4;
        bool rip_rel = (ctx->mode == 64) && (mod == 0) && (rm & 7) == 5;

        if (has_sib && mod != 3) {
            if (pos >= (int)size) return -1;
            uint8_t sib = code[pos++];
            uint8_t scale = (sib >> 6) & 0x3;
            uint8_t index = (sib >> 3) & 0x7;
            uint8_t base = sib & 0x7;

            if (rex & 0x02) index |= 8;  /* REX.X */
            if (rex & 0x01) base |= 8;   /* REX.B */

            rm_op->mem.scale = 1 << scale;

            if (index != 4) {  /* RSP cannot be index */
                rm_op->mem.index = REG64[index];
            }

            if (mod == 0 && (base & 7) == 5) {
                /* disp32 only */
                rm_op->mem.base = E9_X86_REG_NONE;
            } else {
                rm_op->mem.base = REG64[base];
            }

            if (mod == 0 && (base & 7) == 5) {
                if (pos + 4 > (int)size) return -1;
                rm_op->mem.disp = read_i32(&code[pos]);
                pos += 4;
            }
        } else if (rip_rel) {
            rm_op->mem.base = E9_X86_REG_RIP;
        } else if (mod == 0 && (rm & 7) == 5) {
            /* 32-bit mode: disp32 */
            rm_op->mem.base = E9_X86_REG_NONE;
        } else {
            rm_op->mem.base = REG64[rm];
        }

        /* Displacement */
        if (mod == 1) {
            if (pos >= (int)size) return -1;
            rm_op->mem.disp = read_i8(&code[pos]);
            pos += 1;
        } else if (mod == 2 || (mod == 0 && ((rm & 7) == 5 || rip_rel))) {
            if (pos + 4 > (int)size) return -1;
            rm_op->mem.disp = read_i32(&code[pos]);
            pos += 4;
        }
    }

    return pos;
}

/*
 * Disassemble single instruction
 */
int e9_x86_disasm_one(E9X86Disasm *ctx, const uint8_t *code, size_t size,
                      uint64_t address, E9X86Insn *insn)
{
    if (!ctx || !code || size == 0 || !insn) return 0;

    memset(insn, 0, sizeof(*insn));
    insn->address = address;

    int pos = 0;
    uint8_t rex = 0;
    bool has_66 = false;
    bool has_67 = false;
    E9X86Reg seg_override = E9_X86_REG_NONE;

    /* Parse prefixes */
    while (pos < (int)size) {
        uint8_t b = code[pos];

        if (b == 0xF0) { insn->has_lock = true; pos++; }
        else if (b == 0xF2) { insn->has_repne = true; pos++; }
        else if (b == 0xF3) { insn->has_rep = true; pos++; }
        else if (b == 0x2E) { seg_override = E9_X86_REG_CS; pos++; }
        else if (b == 0x36) { seg_override = E9_X86_REG_SS; pos++; }
        else if (b == 0x3E) { seg_override = E9_X86_REG_DS; pos++; }
        else if (b == 0x26) { seg_override = E9_X86_REG_ES; pos++; }
        else if (b == 0x64) { seg_override = E9_X86_REG_FS; pos++; }
        else if (b == 0x65) { seg_override = E9_X86_REG_GS; pos++; }
        else if (b == 0x66) { has_66 = true; pos++; }
        else if (b == 0x67) { has_67 = true; pos++; }
        else if (ctx->mode == 64 && (b >= 0x40 && b <= 0x4F)) {
            rex = b;
            insn->has_rex = true;
            insn->rex = rex;
            pos++;
        }
        else break;
    }

    if (pos >= (int)size) goto invalid;

    /* Determine operand size */
    int op_size = (ctx->mode == 64) ? 4 : ctx->mode / 8;
    if (rex & 0x08) op_size = 8;  /* REX.W */
    if (has_66) op_size = (op_size == 4) ? 2 : 4;

    (void)has_67;
    (void)seg_override;

    /* Decode opcode */
    uint8_t op = code[pos++];

    /* Single-byte opcodes */
    switch (op) {
        /* NOP */
        case 0x90:
            strcpy(insn->mnemonic, "nop");
            insn->category = E9_X86_CAT_NOP;
            break;

        /* PUSH reg */
        case 0x50: case 0x51: case 0x52: case 0x53:
        case 0x54: case 0x55: case 0x56: case 0x57:
            strcpy(insn->mnemonic, "push");
            insn->category = E9_X86_CAT_STACK;
            insn->num_operands = 1;
            insn->operands[0].type = E9_X86_OP_REG;
            insn->operands[0].size = (ctx->mode == 64) ? 8 : 4;
            insn->operands[0].reg = (ctx->mode == 64) ?
                REG64[(op - 0x50) | ((rex & 1) << 3)] :
                REG32[op - 0x50];
            break;

        /* POP reg */
        case 0x58: case 0x59: case 0x5A: case 0x5B:
        case 0x5C: case 0x5D: case 0x5E: case 0x5F:
            strcpy(insn->mnemonic, "pop");
            insn->category = E9_X86_CAT_STACK;
            insn->num_operands = 1;
            insn->operands[0].type = E9_X86_OP_REG;
            insn->operands[0].size = (ctx->mode == 64) ? 8 : 4;
            insn->operands[0].reg = (ctx->mode == 64) ?
                REG64[(op - 0x58) | ((rex & 1) << 3)] :
                REG32[op - 0x58];
            break;

        /* MOV r, imm (B8-BF) */
        case 0xB8: case 0xB9: case 0xBA: case 0xBB:
        case 0xBC: case 0xBD: case 0xBE: case 0xBF:
            strcpy(insn->mnemonic, "mov");
            insn->category = E9_X86_CAT_DATA_XFER;
            insn->num_operands = 2;
            insn->operands[0].type = E9_X86_OP_REG;
            insn->operands[0].size = op_size;
            if (op_size == 8) {
                insn->operands[0].reg = REG64[(op - 0xB8) | ((rex & 1) << 3)];
                if (pos + 8 > (int)size) goto invalid;
                insn->operands[1].type = E9_X86_OP_IMM;
                insn->operands[1].size = 8;
                insn->operands[1].imm = read_i64(&code[pos]);
                pos += 8;
            } else {
                insn->operands[0].reg = REG32[(op - 0xB8) | ((rex & 1) << 3)];
                if (pos + 4 > (int)size) goto invalid;
                insn->operands[1].type = E9_X86_OP_IMM;
                insn->operands[1].size = 4;
                insn->operands[1].imm = read_i32(&code[pos]);
                pos += 4;
            }
            break;

        /* RET */
        case 0xC3:
            strcpy(insn->mnemonic, "ret");
            insn->category = E9_X86_CAT_CONTROL;
            insn->is_ret = true;
            insn->is_branch = true;
            break;

        /* LEAVE */
        case 0xC9:
            strcpy(insn->mnemonic, "leave");
            insn->category = E9_X86_CAT_STACK;
            break;

        /* CALL rel32 */
        case 0xE8:
            strcpy(insn->mnemonic, "call");
            insn->category = E9_X86_CAT_CONTROL;
            insn->is_call = true;
            insn->is_branch = true;
            if (pos + 4 > (int)size) goto invalid;
            insn->num_operands = 1;
            insn->operands[0].type = E9_X86_OP_REL;
            insn->operands[0].rel = read_i32(&code[pos]);
            pos += 4;
            insn->branch_target = address + pos + insn->operands[0].rel;
            break;

        /* JMP rel32 */
        case 0xE9:
            strcpy(insn->mnemonic, "jmp");
            insn->category = E9_X86_CAT_CONTROL;
            insn->is_branch = true;
            if (pos + 4 > (int)size) goto invalid;
            insn->num_operands = 1;
            insn->operands[0].type = E9_X86_OP_REL;
            insn->operands[0].rel = read_i32(&code[pos]);
            pos += 4;
            insn->branch_target = address + pos + insn->operands[0].rel;
            break;

        /* JMP rel8 */
        case 0xEB:
            strcpy(insn->mnemonic, "jmp");
            insn->category = E9_X86_CAT_CONTROL;
            insn->is_branch = true;
            if (pos >= (int)size) goto invalid;
            insn->num_operands = 1;
            insn->operands[0].type = E9_X86_OP_REL;
            insn->operands[0].rel = read_i8(&code[pos]);
            pos += 1;
            insn->branch_target = address + pos + insn->operands[0].rel;
            break;

        /* Jcc rel8 (70-7F) */
        case 0x70: case 0x71: case 0x72: case 0x73:
        case 0x74: case 0x75: case 0x76: case 0x77:
        case 0x78: case 0x79: case 0x7A: case 0x7B:
        case 0x7C: case 0x7D: case 0x7E: case 0x7F: {
            static const char *jcc_names[] = {
                "jo", "jno", "jb", "jnb", "jz", "jnz", "jbe", "ja",
                "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg"
            };
            strcpy(insn->mnemonic, jcc_names[op - 0x70]);
            insn->category = E9_X86_CAT_CONTROL;
            insn->is_branch = true;
            insn->is_conditional = true;
            if (pos >= (int)size) goto invalid;
            insn->num_operands = 1;
            insn->operands[0].type = E9_X86_OP_REL;
            insn->operands[0].rel = read_i8(&code[pos]);
            pos += 1;
            insn->branch_target = address + pos + insn->operands[0].rel;
            break;
        }

        /* Two-byte opcodes (0F xx) */
        case 0x0F: {
            if (pos >= (int)size) goto invalid;
            uint8_t op2 = code[pos++];

            /* Jcc rel32 (0F 80 - 0F 8F) */
            if (op2 >= 0x80 && op2 <= 0x8F) {
                static const char *jcc_names[] = {
                    "jo", "jno", "jb", "jnb", "jz", "jnz", "jbe", "ja",
                    "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg"
                };
                strcpy(insn->mnemonic, jcc_names[op2 - 0x80]);
                insn->category = E9_X86_CAT_CONTROL;
                insn->is_branch = true;
                insn->is_conditional = true;
                if (pos + 4 > (int)size) goto invalid;
                insn->num_operands = 1;
                insn->operands[0].type = E9_X86_OP_REL;
                insn->operands[0].rel = read_i32(&code[pos]);
                pos += 4;
                insn->branch_target = address + pos + insn->operands[0].rel;
            }
            /* SYSCALL */
            else if (op2 == 0x05) {
                strcpy(insn->mnemonic, "syscall");
                insn->category = E9_X86_CAT_SYSTEM;
            }
            /* SYSRET */
            else if (op2 == 0x07) {
                strcpy(insn->mnemonic, "sysret");
                insn->category = E9_X86_CAT_SYSTEM;
            }
            /* CPUID */
            else if (op2 == 0xA2) {
                strcpy(insn->mnemonic, "cpuid");
                insn->category = E9_X86_CAT_SYSTEM;
            }
            /* NOP (multi-byte) */
            else if (op2 == 0x1F) {
                strcpy(insn->mnemonic, "nop");
                insn->category = E9_X86_CAT_NOP;
                /* Skip ModR/M and any displacement */
                pos = decode_modrm(ctx, code, size, pos, rex, op_size, NULL, NULL);
                if (pos < 0) goto invalid;
            }
            else {
                snprintf(insn->mnemonic, sizeof(insn->mnemonic), "0f %02x", op2);
                insn->category = E9_X86_CAT_OTHER;
            }
            break;
        }

        /* MOV r/m, r (89) */
        case 0x89:
            strcpy(insn->mnemonic, "mov");
            insn->category = E9_X86_CAT_DATA_XFER;
            insn->num_operands = 2;
            pos = decode_modrm(ctx, code, size, pos, rex, op_size,
                               &insn->operands[1], &insn->operands[0]);
            if (pos < 0) goto invalid;
            if (insn->operands[0].type == E9_X86_OP_MEM) {
                insn->writes_memory = true;
            }
            break;

        /* MOV r, r/m (8B) */
        case 0x8B:
            strcpy(insn->mnemonic, "mov");
            insn->category = E9_X86_CAT_DATA_XFER;
            insn->num_operands = 2;
            pos = decode_modrm(ctx, code, size, pos, rex, op_size,
                               &insn->operands[0], &insn->operands[1]);
            if (pos < 0) goto invalid;
            if (insn->operands[1].type == E9_X86_OP_MEM) {
                insn->reads_memory = true;
            }
            break;

        /* LEA r, m (8D) */
        case 0x8D:
            strcpy(insn->mnemonic, "lea");
            insn->category = E9_X86_CAT_DATA_XFER;
            insn->num_operands = 2;
            pos = decode_modrm(ctx, code, size, pos, rex, op_size,
                               &insn->operands[0], &insn->operands[1]);
            if (pos < 0) goto invalid;
            break;

        /* XOR r/m, r (31) */
        case 0x31:
            strcpy(insn->mnemonic, "xor");
            insn->category = E9_X86_CAT_LOGICAL;
            insn->num_operands = 2;
            pos = decode_modrm(ctx, code, size, pos, rex, op_size,
                               &insn->operands[1], &insn->operands[0]);
            if (pos < 0) goto invalid;
            break;

        /* ADD/OR/ADC/SBB/AND/SUB/XOR/CMP r/m, imm (83) */
        case 0x83: {
            if (pos >= (int)size) goto invalid;
            uint8_t modrm = code[pos];
            uint8_t op_ext = (modrm >> 3) & 7;
            static const char *grp1[] = {
                "add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"
            };
            strcpy(insn->mnemonic, grp1[op_ext]);
            insn->category = (op_ext == 7) ? E9_X86_CAT_COMPARE :
                             (op_ext < 2 || op_ext == 4 || op_ext == 6) ?
                             E9_X86_CAT_LOGICAL : E9_X86_CAT_ARITHMETIC;
            insn->num_operands = 2;
            pos = decode_modrm(ctx, code, size, pos, rex, op_size,
                               NULL, &insn->operands[0]);
            if (pos < 0 || pos >= (int)size) goto invalid;
            insn->operands[1].type = E9_X86_OP_IMM;
            insn->operands[1].size = 1;
            insn->operands[1].imm = read_i8(&code[pos]);
            pos += 1;
            break;
        }

        /* TEST r/m, r (85) */
        case 0x85:
            strcpy(insn->mnemonic, "test");
            insn->category = E9_X86_CAT_COMPARE;
            insn->num_operands = 2;
            pos = decode_modrm(ctx, code, size, pos, rex, op_size,
                               &insn->operands[1], &insn->operands[0]);
            if (pos < 0) goto invalid;
            break;

        /* CMP r/m, r (39) */
        case 0x39:
            strcpy(insn->mnemonic, "cmp");
            insn->category = E9_X86_CAT_COMPARE;
            insn->num_operands = 2;
            pos = decode_modrm(ctx, code, size, pos, rex, op_size,
                               &insn->operands[1], &insn->operands[0]);
            if (pos < 0) goto invalid;
            break;

        /* INT 3 */
        case 0xCC:
            strcpy(insn->mnemonic, "int3");
            insn->category = E9_X86_CAT_CONTROL;
            break;

        /* HLT */
        case 0xF4:
            strcpy(insn->mnemonic, "hlt");
            insn->category = E9_X86_CAT_SYSTEM;
            break;

        /* Default: unknown opcode */
        default:
            snprintf(insn->mnemonic, sizeof(insn->mnemonic), "db 0x%02x", op);
            insn->category = E9_X86_CAT_INVALID;
            break;
    }

    /* Set length and copy bytes */
    insn->length = pos;
    memcpy(insn->bytes, code, (pos > 15) ? 15 : pos);

    /* Format text */
    e9_x86_insn_format(insn, insn->text, sizeof(insn->text));

    return pos;

invalid:
    insn->length = 1;
    insn->bytes[0] = code[0];
    strcpy(insn->mnemonic, "(bad)");
    insn->category = E9_X86_CAT_INVALID;
    snprintf(insn->text, sizeof(insn->text), "(bad)");
    return 1;
}

/*
 * Format instruction to string
 */
void e9_x86_insn_format(const E9X86Insn *insn, char *buf, size_t size)
{
    if (!insn || !buf || size == 0) return;

    char *p = buf;
    char *end = buf + size - 1;

    /* Prefixes */
    if (insn->has_lock) p += snprintf(p, end - p, "lock ");
    if (insn->has_rep) p += snprintf(p, end - p, "rep ");
    if (insn->has_repne) p += snprintf(p, end - p, "repne ");

    /* Mnemonic */
    p += snprintf(p, end - p, "%s", insn->mnemonic);

    /* Operands */
    for (int i = 0; i < insn->num_operands && p < end; i++) {
        p += snprintf(p, end - p, "%s", (i == 0) ? " " : ", ");

        const E9X86Operand *op = &insn->operands[i];
        switch (op->type) {
            case E9_X86_OP_REG:
                p += snprintf(p, end - p, "%s", e9_x86_reg_name(op->reg));
                break;

            case E9_X86_OP_IMM:
                if (op->imm < 0) {
                    p += snprintf(p, end - p, "-0x%llx", (unsigned long long)-op->imm);
                } else {
                    p += snprintf(p, end - p, "0x%llx", (unsigned long long)op->imm);
                }
                break;

            case E9_X86_OP_REL:
                p += snprintf(p, end - p, "0x%llx", (unsigned long long)insn->branch_target);
                break;

            case E9_X86_OP_MEM:
                /* Memory operand */
                p += snprintf(p, end - p, "[");
                bool need_plus = false;

                if (op->mem.base != E9_X86_REG_NONE) {
                    p += snprintf(p, end - p, "%s", e9_x86_reg_name(op->mem.base));
                    need_plus = true;
                }

                if (op->mem.index != E9_X86_REG_NONE) {
                    if (need_plus) p += snprintf(p, end - p, "+");
                    p += snprintf(p, end - p, "%s", e9_x86_reg_name(op->mem.index));
                    if (op->mem.scale > 1) {
                        p += snprintf(p, end - p, "*%d", op->mem.scale);
                    }
                    need_plus = true;
                }

                if (op->mem.disp != 0 || !need_plus) {
                    if (op->mem.disp >= 0) {
                        if (need_plus) p += snprintf(p, end - p, "+");
                        p += snprintf(p, end - p, "0x%llx", (unsigned long long)op->mem.disp);
                    } else {
                        p += snprintf(p, end - p, "-0x%llx", (unsigned long long)-op->mem.disp);
                    }
                }

                p += snprintf(p, end - p, "]");
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
size_t e9_x86_disasm(E9X86Disasm *ctx, const uint8_t *code, size_t size,
                     uint64_t address, size_t count, E9X86Insn **insns)
{
    if (!ctx || !code || size == 0 || !insns) return 0;

    *insns = calloc(count, sizeof(E9X86Insn));
    if (!*insns) return 0;

    size_t decoded = 0;
    size_t offset = 0;

    while (decoded < count && offset < size) {
        int len = e9_x86_disasm_one(ctx, code + offset, size - offset,
                                     address + offset, &(*insns)[decoded]);
        if (len <= 0) break;

        offset += len;
        decoded++;
    }

    return decoded;
}

/*
 * Free instruction array
 */
void e9_x86_insns_free(E9X86Insn *insns, size_t count)
{
    (void)count;
    free(insns);
}

/*
 * Check for function prologue
 */
bool e9_x86_is_prologue(const uint8_t *code, size_t size)
{
    if (size < 1) return false;

    /* push rbp; mov rbp, rsp */
    if (size >= 4 && code[0] == 0x55 &&
        code[1] == 0x48 && code[2] == 0x89 && code[3] == 0xE5) {
        return true;
    }

    /* push rbp (might be followed by other setup) */
    if (code[0] == 0x55) return true;

    /* endbr64 (CET) followed by push */
    if (size >= 5 && code[0] == 0xF3 && code[1] == 0x0F &&
        code[2] == 0x1E && code[3] == 0xFA && code[4] == 0x55) {
        return true;
    }

    return false;
}

/*
 * Check for function epilogue
 */
bool e9_x86_is_epilogue(const uint8_t *code, size_t size)
{
    if (size < 1) return false;

    /* ret */
    if (code[0] == 0xC3) return true;

    /* leave; ret */
    if (size >= 2 && code[0] == 0xC9 && code[1] == 0xC3) return true;

    /* pop rbp; ret */
    if (size >= 2 && code[0] == 0x5D && code[1] == 0xC3) return true;

    return false;
}

/*
 * Get instruction length (quick estimate)
 */
int e9_x86_insn_length(const uint8_t *code, size_t size, int mode)
{
    E9X86Disasm *ctx = e9_x86_disasm_create(mode);
    if (!ctx) return 0;

    E9X86Insn insn;
    int len = e9_x86_disasm_one(ctx, code, size, 0, &insn);

    e9_x86_disasm_free(ctx);
    return len;
}

/*
 * Check if bytes could be valid instruction
 */
bool e9_x86_is_valid_opcode(const uint8_t *code, size_t size, int mode)
{
    if (size < 1) return false;

    E9X86Disasm *ctx = e9_x86_disasm_create(mode);
    if (!ctx) return false;

    E9X86Insn insn;
    int len = e9_x86_disasm_one(ctx, code, size, 0, &insn);

    e9_x86_disasm_free(ctx);

    return len > 0 && insn.category != E9_X86_CAT_INVALID;
}

/*
 * Check if instruction writes register
 */
bool e9_x86_insn_writes_reg(const E9X86Insn *insn, E9X86Reg reg)
{
    if (!insn || insn->num_operands == 0) return false;

    /* Most instructions write to first operand */
    if (insn->operands[0].type == E9_X86_OP_REG &&
        insn->operands[0].reg == reg) {
        return true;
    }

    /* Special cases */
    if (strcmp(insn->mnemonic, "push") == 0 && reg == E9_X86_REG_RSP) {
        return true;
    }
    if (strcmp(insn->mnemonic, "pop") == 0 && reg == E9_X86_REG_RSP) {
        return true;
    }
    if (strcmp(insn->mnemonic, "call") == 0 && reg == E9_X86_REG_RSP) {
        return true;
    }

    return false;
}

/*
 * Check if instruction reads register
 */
bool e9_x86_insn_reads_reg(const E9X86Insn *insn, E9X86Reg reg)
{
    if (!insn) return false;

    for (int i = 0; i < insn->num_operands; i++) {
        const E9X86Operand *op = &insn->operands[i];

        if (op->type == E9_X86_OP_REG && op->reg == reg) {
            /* Skip destination for non-compare instructions */
            if (i == 0 && strcmp(insn->mnemonic, "cmp") != 0 &&
                strcmp(insn->mnemonic, "test") != 0) {
                continue;
            }
            return true;
        }

        if (op->type == E9_X86_OP_MEM) {
            if (op->mem.base == reg || op->mem.index == reg) {
                return true;
            }
        }
    }

    return false;
}
