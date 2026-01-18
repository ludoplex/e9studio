/*
 * e9disasm_arm64.h
 * Lightweight AArch64 (ARM64) Disassembler
 *
 * A self-contained, minimal AArch64 disassembler suitable for
 * binary analysis without external dependencies.
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

#ifndef E9DISASM_ARM64_H
#define E9DISASM_ARM64_H

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
    E9_A64_CAT_INVALID = 0,
    E9_A64_CAT_DATA_PROC,       /* Data processing (add, sub, and, orr, etc.) */
    E9_A64_CAT_LOAD_STORE,      /* Load/store instructions */
    E9_A64_CAT_BRANCH,          /* Branch instructions */
    E9_A64_CAT_SIMD_FP,         /* SIMD and floating-point */
    E9_A64_CAT_SYSTEM,          /* System instructions */
    E9_A64_CAT_EXCEPTION,       /* Exception generation */
    E9_A64_CAT_BITFIELD,        /* Bit manipulation */
    E9_A64_CAT_MOVE,            /* Move instructions */
    E9_A64_CAT_COMPARE,         /* Compare instructions */
    E9_A64_CAT_OTHER,
} E9A64Category;

/*
 * Operand types
 */
typedef enum {
    E9_A64_OP_NONE = 0,
    E9_A64_OP_REG,              /* General-purpose register */
    E9_A64_OP_VREG,             /* SIMD/FP register */
    E9_A64_OP_IMM,              /* Immediate value */
    E9_A64_OP_MEM,              /* Memory reference */
    E9_A64_OP_LABEL,            /* PC-relative label */
    E9_A64_OP_SHIFT,            /* Shifted register */
    E9_A64_OP_EXTEND,           /* Extended register */
    E9_A64_OP_COND,             /* Condition code */
    E9_A64_OP_SYSREG,           /* System register */
} E9A64OpType;

/*
 * General-purpose registers
 */
typedef enum {
    E9_A64_REG_X0 = 0, E9_A64_REG_X1, E9_A64_REG_X2, E9_A64_REG_X3,
    E9_A64_REG_X4, E9_A64_REG_X5, E9_A64_REG_X6, E9_A64_REG_X7,
    E9_A64_REG_X8, E9_A64_REG_X9, E9_A64_REG_X10, E9_A64_REG_X11,
    E9_A64_REG_X12, E9_A64_REG_X13, E9_A64_REG_X14, E9_A64_REG_X15,
    E9_A64_REG_X16, E9_A64_REG_X17, E9_A64_REG_X18, E9_A64_REG_X19,
    E9_A64_REG_X20, E9_A64_REG_X21, E9_A64_REG_X22, E9_A64_REG_X23,
    E9_A64_REG_X24, E9_A64_REG_X25, E9_A64_REG_X26, E9_A64_REG_X27,
    E9_A64_REG_X28, E9_A64_REG_X29, E9_A64_REG_X30, E9_A64_REG_XZR,
    E9_A64_REG_SP,

    /* 32-bit aliases */
    E9_A64_REG_W0 = 64, E9_A64_REG_W1, E9_A64_REG_W2, E9_A64_REG_W3,
    E9_A64_REG_W4, E9_A64_REG_W5, E9_A64_REG_W6, E9_A64_REG_W7,
    E9_A64_REG_W8, E9_A64_REG_W9, E9_A64_REG_W10, E9_A64_REG_W11,
    E9_A64_REG_W12, E9_A64_REG_W13, E9_A64_REG_W14, E9_A64_REG_W15,
    E9_A64_REG_W16, E9_A64_REG_W17, E9_A64_REG_W18, E9_A64_REG_W19,
    E9_A64_REG_W20, E9_A64_REG_W21, E9_A64_REG_W22, E9_A64_REG_W23,
    E9_A64_REG_W24, E9_A64_REG_W25, E9_A64_REG_W26, E9_A64_REG_W27,
    E9_A64_REG_W28, E9_A64_REG_W29, E9_A64_REG_W30, E9_A64_REG_WZR,
    E9_A64_REG_WSP,

    /* Special aliases */
    E9_A64_REG_LR = E9_A64_REG_X30,
    E9_A64_REG_FP = E9_A64_REG_X29,
} E9A64Reg;

/*
 * SIMD/FP registers
 */
typedef enum {
    E9_A64_VREG_V0 = 0, E9_A64_VREG_V1, E9_A64_VREG_V2, E9_A64_VREG_V3,
    E9_A64_VREG_V4, E9_A64_VREG_V5, E9_A64_VREG_V6, E9_A64_VREG_V7,
    E9_A64_VREG_V8, E9_A64_VREG_V9, E9_A64_VREG_V10, E9_A64_VREG_V11,
    E9_A64_VREG_V12, E9_A64_VREG_V13, E9_A64_VREG_V14, E9_A64_VREG_V15,
    E9_A64_VREG_V16, E9_A64_VREG_V17, E9_A64_VREG_V18, E9_A64_VREG_V19,
    E9_A64_VREG_V20, E9_A64_VREG_V21, E9_A64_VREG_V22, E9_A64_VREG_V23,
    E9_A64_VREG_V24, E9_A64_VREG_V25, E9_A64_VREG_V26, E9_A64_VREG_V27,
    E9_A64_VREG_V28, E9_A64_VREG_V29, E9_A64_VREG_V30, E9_A64_VREG_V31,
} E9A64VReg;

/*
 * Shift types
 */
typedef enum {
    E9_A64_SHIFT_LSL = 0,       /* Logical shift left */
    E9_A64_SHIFT_LSR,           /* Logical shift right */
    E9_A64_SHIFT_ASR,           /* Arithmetic shift right */
    E9_A64_SHIFT_ROR,           /* Rotate right */
} E9A64Shift;

/*
 * Extend types
 */
typedef enum {
    E9_A64_EXT_UXTB = 0,        /* Unsigned extend byte */
    E9_A64_EXT_UXTH,            /* Unsigned extend halfword */
    E9_A64_EXT_UXTW,            /* Unsigned extend word */
    E9_A64_EXT_UXTX,            /* Unsigned extend doubleword */
    E9_A64_EXT_SXTB,            /* Signed extend byte */
    E9_A64_EXT_SXTH,            /* Signed extend halfword */
    E9_A64_EXT_SXTW,            /* Signed extend word */
    E9_A64_EXT_SXTX,            /* Signed extend doubleword */
} E9A64Extend;

/*
 * Condition codes
 */
typedef enum {
    E9_A64_COND_EQ = 0,         /* Equal */
    E9_A64_COND_NE,             /* Not equal */
    E9_A64_COND_CS,             /* Carry set / unsigned higher or same */
    E9_A64_COND_CC,             /* Carry clear / unsigned lower */
    E9_A64_COND_MI,             /* Minus / negative */
    E9_A64_COND_PL,             /* Plus / positive or zero */
    E9_A64_COND_VS,             /* Overflow */
    E9_A64_COND_VC,             /* No overflow */
    E9_A64_COND_HI,             /* Unsigned higher */
    E9_A64_COND_LS,             /* Unsigned lower or same */
    E9_A64_COND_GE,             /* Signed greater or equal */
    E9_A64_COND_LT,             /* Signed less than */
    E9_A64_COND_GT,             /* Signed greater than */
    E9_A64_COND_LE,             /* Signed less or equal */
    E9_A64_COND_AL,             /* Always */
    E9_A64_COND_NV,             /* Never (reserved) */
} E9A64Cond;

/*
 * Operand
 */
typedef struct {
    E9A64OpType type;
    uint8_t size;               /* Size in bytes */

    union {
        /* Register operand */
        E9A64Reg reg;

        /* Vector register */
        struct {
            E9A64VReg reg;
            uint8_t elem_size;  /* Element size (1, 2, 4, 8) */
            int8_t index;       /* Element index (-1 if full register) */
        } vreg;

        /* Immediate */
        int64_t imm;

        /* Memory operand */
        struct {
            E9A64Reg base;
            E9A64Reg index;
            int64_t offset;
            E9A64Shift shift;
            uint8_t shift_amount;
            E9A64Extend extend;
            bool pre_index;     /* Pre-indexed */
            bool post_index;    /* Post-indexed */
        } mem;

        /* PC-relative label */
        int64_t label;

        /* Shifted register */
        struct {
            E9A64Reg reg;
            E9A64Shift shift;
            uint8_t amount;
        } shifted;

        /* Extended register */
        struct {
            E9A64Reg reg;
            E9A64Extend extend;
            uint8_t shift;
        } extended;

        /* Condition code */
        E9A64Cond cond;
    };
} E9A64Operand;

/*
 * Decoded instruction
 */
typedef struct {
    uint64_t address;           /* Address of instruction */
    uint32_t encoding;          /* Raw 32-bit encoding */

    /* Mnemonic */
    char mnemonic[16];

    /* Category */
    E9A64Category category;

    /* Operands */
    E9A64Operand operands[5];
    uint8_t num_operands;

    /* Control flow info */
    bool is_branch;
    bool is_call;
    bool is_ret;
    bool is_conditional;
    uint64_t branch_target;

    /* Memory access info */
    bool reads_memory;
    bool writes_memory;

    /* For textual output */
    char text[80];

} E9A64Insn;

/*
 * Disassembler context
 */
typedef struct E9A64Disasm E9A64Disasm;

/*
 * Create disassembler
 */
E9A64Disasm *e9_a64_disasm_create(void);

/*
 * Free disassembler
 */
void e9_a64_disasm_free(E9A64Disasm *ctx);

/*
 * Disassemble single instruction
 * Returns 4 on success (AArch64 instructions are always 4 bytes), 0 on error
 */
int e9_a64_disasm_one(E9A64Disasm *ctx, const uint8_t *code, size_t size,
                      uint64_t address, E9A64Insn *insn);

/*
 * Disassemble multiple instructions
 */
size_t e9_a64_disasm(E9A64Disasm *ctx, const uint8_t *code, size_t size,
                     uint64_t address, size_t count, E9A64Insn **insns);

/*
 * Free instruction array
 */
void e9_a64_insns_free(E9A64Insn *insns, size_t count);

/*
 * Get register name
 */
const char *e9_a64_reg_name(E9A64Reg reg);

/*
 * Get condition code name
 */
const char *e9_a64_cond_name(E9A64Cond cond);

/*
 * Format instruction to string
 */
void e9_a64_insn_format(const E9A64Insn *insn, char *buf, size_t size);

/*
 * Check for function prologue
 */
bool e9_a64_is_prologue(const uint8_t *code, size_t size);

/*
 * Check for function epilogue
 */
bool e9_a64_is_epilogue(const uint8_t *code, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* E9DISASM_ARM64_H */
