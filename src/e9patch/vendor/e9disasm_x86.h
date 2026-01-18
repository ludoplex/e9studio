/*
 * e9disasm_x86.h
 * Lightweight x86-64 Disassembler
 *
 * A self-contained, minimal x86-64 disassembler suitable for
 * binary analysis without external dependencies.
 *
 * Covers the most common instructions encountered in typical binaries.
 * For full disassembly, can fall back to capstone if available.
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

#ifndef E9DISASM_X86_H
#define E9DISASM_X86_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Instruction categories
 */
typedef enum {
    E9_X86_CAT_INVALID = 0,
    E9_X86_CAT_DATA_XFER,       /* mov, push, pop, xchg, lea */
    E9_X86_CAT_ARITHMETIC,      /* add, sub, mul, div, inc, dec */
    E9_X86_CAT_LOGICAL,         /* and, or, xor, not, test */
    E9_X86_CAT_SHIFT,           /* shl, shr, sar, rol, ror */
    E9_X86_CAT_CONTROL,         /* jmp, jcc, call, ret, int */
    E9_X86_CAT_STRING,          /* movs, cmps, scas, lods, stos */
    E9_X86_CAT_FLAG,            /* stc, clc, cld, std */
    E9_X86_CAT_STACK,           /* push, pop, enter, leave */
    E9_X86_CAT_COMPARE,         /* cmp, test */
    E9_X86_CAT_SIMD,            /* SSE/AVX instructions */
    E9_X86_CAT_SYSTEM,          /* syscall, sysenter, cpuid */
    E9_X86_CAT_NOP,             /* nop, pause */
    E9_X86_CAT_OTHER,
} E9X86Category;

/*
 * Operand types
 */
typedef enum {
    E9_X86_OP_NONE = 0,
    E9_X86_OP_REG,              /* Register */
    E9_X86_OP_MEM,              /* Memory reference */
    E9_X86_OP_IMM,              /* Immediate value */
    E9_X86_OP_REL,              /* Relative offset (for jumps/calls) */
} E9X86OpType;

/*
 * Register IDs (simplified)
 */
typedef enum {
    E9_X86_REG_NONE = 0,

    /* 64-bit */
    E9_X86_REG_RAX, E9_X86_REG_RCX, E9_X86_REG_RDX, E9_X86_REG_RBX,
    E9_X86_REG_RSP, E9_X86_REG_RBP, E9_X86_REG_RSI, E9_X86_REG_RDI,
    E9_X86_REG_R8,  E9_X86_REG_R9,  E9_X86_REG_R10, E9_X86_REG_R11,
    E9_X86_REG_R12, E9_X86_REG_R13, E9_X86_REG_R14, E9_X86_REG_R15,
    E9_X86_REG_RIP,

    /* 32-bit */
    E9_X86_REG_EAX, E9_X86_REG_ECX, E9_X86_REG_EDX, E9_X86_REG_EBX,
    E9_X86_REG_ESP, E9_X86_REG_EBP, E9_X86_REG_ESI, E9_X86_REG_EDI,
    E9_X86_REG_R8D, E9_X86_REG_R9D, E9_X86_REG_R10D, E9_X86_REG_R11D,
    E9_X86_REG_R12D, E9_X86_REG_R13D, E9_X86_REG_R14D, E9_X86_REG_R15D,
    E9_X86_REG_EIP,

    /* 16-bit */
    E9_X86_REG_AX, E9_X86_REG_CX, E9_X86_REG_DX, E9_X86_REG_BX,
    E9_X86_REG_SP, E9_X86_REG_BP, E9_X86_REG_SI, E9_X86_REG_DI,

    /* 8-bit */
    E9_X86_REG_AL, E9_X86_REG_CL, E9_X86_REG_DL, E9_X86_REG_BL,
    E9_X86_REG_AH, E9_X86_REG_CH, E9_X86_REG_DH, E9_X86_REG_BH,
    E9_X86_REG_SPL, E9_X86_REG_BPL, E9_X86_REG_SIL, E9_X86_REG_DIL,

    /* Segment registers */
    E9_X86_REG_CS, E9_X86_REG_DS, E9_X86_REG_ES,
    E9_X86_REG_FS, E9_X86_REG_GS, E9_X86_REG_SS,

    /* XMM registers */
    E9_X86_REG_XMM0, E9_X86_REG_XMM1, E9_X86_REG_XMM2, E9_X86_REG_XMM3,
    E9_X86_REG_XMM4, E9_X86_REG_XMM5, E9_X86_REG_XMM6, E9_X86_REG_XMM7,
    E9_X86_REG_XMM8, E9_X86_REG_XMM9, E9_X86_REG_XMM10, E9_X86_REG_XMM11,
    E9_X86_REG_XMM12, E9_X86_REG_XMM13, E9_X86_REG_XMM14, E9_X86_REG_XMM15,

} E9X86Reg;

/*
 * Operand
 */
typedef struct {
    E9X86OpType type;
    uint8_t size;               /* Size in bytes (1, 2, 4, 8, 16, 32) */

    union {
        /* Register operand */
        E9X86Reg reg;

        /* Immediate operand */
        int64_t imm;

        /* Relative offset */
        int64_t rel;

        /* Memory operand */
        struct {
            E9X86Reg base;
            E9X86Reg index;
            uint8_t scale;      /* 1, 2, 4, or 8 */
            int64_t disp;
            E9X86Reg segment;   /* Segment override (or NONE) */
        } mem;
    };
} E9X86Operand;

/*
 * Decoded instruction
 */
typedef struct {
    uint64_t address;           /* Address of instruction */
    uint8_t length;             /* Length in bytes */
    uint8_t bytes[15];          /* Raw bytes (max x86 instruction = 15) */

    /* Mnemonic */
    char mnemonic[16];

    /* Category */
    E9X86Category category;

    /* Operands */
    E9X86Operand operands[4];
    uint8_t num_operands;

    /* Prefixes */
    bool has_lock;
    bool has_rep;
    bool has_repne;
    bool has_rex;
    uint8_t rex;                /* REX byte if present */

    /* Control flow info */
    bool is_branch;             /* Any branch (jmp, jcc, call) */
    bool is_call;
    bool is_ret;
    bool is_conditional;        /* Conditional branch */
    uint64_t branch_target;     /* Target address if computable */

    /* Memory access info */
    bool reads_memory;
    bool writes_memory;

    /* For textual output */
    char text[64];              /* Full disassembly text */

} E9X86Insn;

/*
 * Disassembler context
 */
typedef struct E9X86Disasm E9X86Disasm;

/*
 * Create disassembler (mode: 16, 32, or 64)
 */
E9X86Disasm *e9_x86_disasm_create(int mode);

/*
 * Free disassembler
 */
void e9_x86_disasm_free(E9X86Disasm *ctx);

/*
 * Disassemble single instruction
 * Returns number of bytes consumed, or 0 on error
 */
int e9_x86_disasm_one(E9X86Disasm *ctx, const uint8_t *code, size_t size,
                      uint64_t address, E9X86Insn *insn);

/*
 * Disassemble multiple instructions
 * Returns number of instructions decoded
 */
size_t e9_x86_disasm(E9X86Disasm *ctx, const uint8_t *code, size_t size,
                     uint64_t address, size_t count, E9X86Insn **insns);

/*
 * Free instruction array
 */
void e9_x86_insns_free(E9X86Insn *insns, size_t count);

/*
 * Get register name
 */
const char *e9_x86_reg_name(E9X86Reg reg);

/*
 * Get register size in bytes
 */
int e9_x86_reg_size(E9X86Reg reg);

/*
 * Check if instruction modifies specific register
 */
bool e9_x86_insn_writes_reg(const E9X86Insn *insn, E9X86Reg reg);

/*
 * Check if instruction reads specific register
 */
bool e9_x86_insn_reads_reg(const E9X86Insn *insn, E9X86Reg reg);

/*
 * Format instruction to string
 */
void e9_x86_insn_format(const E9X86Insn *insn, char *buf, size_t size);

/*
 * ============================================================================
 * Common instruction patterns
 * ============================================================================
 */

/*
 * Check for function prologue patterns
 */
bool e9_x86_is_prologue(const uint8_t *code, size_t size);

/*
 * Check for function epilogue patterns
 */
bool e9_x86_is_epilogue(const uint8_t *code, size_t size);

/*
 * Get instruction length without full decode
 */
int e9_x86_insn_length(const uint8_t *code, size_t size, int mode);

/*
 * Check if bytes could be valid instruction start
 */
bool e9_x86_is_valid_opcode(const uint8_t *code, size_t size, int mode);

#ifdef __cplusplus
}
#endif

#endif /* E9DISASM_X86_H */
