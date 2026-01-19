/*
 * e9decompile.h
 * True C Decompilation Engine
 *
 * Produces compilable Cosmopolitan C code from binary analysis.
 * Unlike pseudo-C, the output can be directly compiled with cosmocc.
 *
 * Key features:
 * - Control flow structuring (if/while/for/switch, no gotos)
 * - Expression reconstruction from instruction sequences
 * - Type inference and propagation
 * - Cosmopolitan-specific type mappings
 * - Variable recovery and naming
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

#ifndef E9DECOMPILE_H
#define E9DECOMPILE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Forward declarations from e9analysis.h
 */
struct E9Binary;
struct E9Function;
struct E9BasicBlock;
struct E9CFG;
struct E9Type;

/*
 * ============================================================================
 * Intermediate Representation (IR)
 * ============================================================================
 */

/*
 * IR Operation types
 */
typedef enum {
    /* Constants and variables */
    E9_IR_CONST,        /* Immediate constant */
    E9_IR_REG,          /* Register reference */
    E9_IR_LOCAL,        /* Local variable */
    E9_IR_GLOBAL,       /* Global variable */
    E9_IR_PARAM,        /* Function parameter */
    E9_IR_TEMP,         /* Temporary */

    /* Memory operations */
    E9_IR_LOAD,         /* Load from memory */
    E9_IR_STORE,        /* Store to memory */

    /* Arithmetic */
    E9_IR_ADD,
    E9_IR_SUB,
    E9_IR_MUL,
    E9_IR_DIV,
    E9_IR_MOD,
    E9_IR_NEG,

    /* Bitwise */
    E9_IR_AND,
    E9_IR_OR,
    E9_IR_XOR,
    E9_IR_NOT,
    E9_IR_SHL,
    E9_IR_SHR,
    E9_IR_SAR,          /* Arithmetic shift right */

    /* Comparison (produces bool) */
    E9_IR_EQ,
    E9_IR_NE,
    E9_IR_LT,
    E9_IR_LE,
    E9_IR_GT,
    E9_IR_GE,
    E9_IR_LTU,          /* Unsigned comparisons */
    E9_IR_LEU,
    E9_IR_GTU,
    E9_IR_GEU,

    /* Type conversion */
    E9_IR_CAST,
    E9_IR_SEXT,         /* Sign extend */
    E9_IR_ZEXT,         /* Zero extend */
    E9_IR_TRUNC,        /* Truncate */

    /* Control flow */
    E9_IR_CALL,
    E9_IR_RET,
    E9_IR_BRANCH,       /* Conditional branch */
    E9_IR_GOTO,         /* Unconditional */

    /* Special */
    E9_IR_PHI,          /* SSA phi node */
    E9_IR_ADDRESS,      /* Address-of */
    E9_IR_DEREF,        /* Dereference */
    E9_IR_MEMBER,       /* Struct member access */
    E9_IR_INDEX,        /* Array indexing */
} E9IROp;

/*
 * IR Value (expression tree node)
 */
typedef struct E9IRValue {
    E9IROp op;
    struct E9Type *type;    /* Inferred type */

    union {
        int64_t constant;   /* For E9_IR_CONST */
        int reg;            /* For E9_IR_REG */
        struct {
            int index;
            const char *name;
        } var;              /* For E9_IR_LOCAL/GLOBAL/PARAM/TEMP */
        struct {
            struct E9IRValue *left;
            struct E9IRValue *right;
        } binary;           /* For binary ops */
        struct {
            struct E9IRValue *operand;
        } unary;            /* For unary ops */
        struct {
            struct E9IRValue *addr;
            int size;       /* Load/store size */
        } mem;
        struct {
            struct E9IRValue *func;
            struct E9IRValue **args;
            int num_args;
        } call;
        struct {
            struct E9IRValue *cond;
            int true_block;
            int false_block;
        } branch;
        struct {
            struct E9IRValue **values;
            int *from_blocks;
            int num_values;
        } phi;
    };

    /* Original address for debugging */
    uint64_t addr;

    /* Linked list for statements */
    struct E9IRValue *next;
} E9IRValue;

/*
 * IR Statement (assignment or side effect)
 */
typedef struct E9IRStmt {
    E9IRValue *dest;        /* Destination (or NULL for pure side effects) */
    E9IRValue *value;       /* Source expression */
    uint64_t addr;          /* Original instruction address */
    struct E9IRStmt *next;
} E9IRStmt;

/*
 * IR Basic Block
 */
typedef struct E9IRBlock {
    int id;
    E9IRStmt *first_stmt;
    E9IRStmt *last_stmt;
    int num_stmts;

    /* Structured control flow info */
    struct {
        enum {
            E9_STRUCT_SEQ,      /* Sequential */
            E9_STRUCT_IF,       /* if-then[-else] */
            E9_STRUCT_WHILE,    /* while loop */
            E9_STRUCT_DOWHILE,  /* do-while loop */
            E9_STRUCT_FOR,      /* for loop */
            E9_STRUCT_SWITCH,   /* switch statement */
            E9_STRUCT_BREAK,    /* break */
            E9_STRUCT_CONTINUE, /* continue */
        } type;

        E9IRValue *condition;   /* For if/while */
        struct E9IRBlock *then_block;
        struct E9IRBlock *else_block;
        struct E9IRBlock *body;
        struct E9IRBlock *increment; /* For for loops */
    } structured;

    /* Original CFG info */
    struct E9BasicBlock *original;
} E9IRBlock;

/*
 * IR Function
 */
typedef struct E9IRFunc {
    const char *name;
    struct E9Type *return_type;

    /* Parameters */
    struct {
        const char *name;
        struct E9Type *type;
    } *params;
    int num_params;

    /* Locals */
    struct {
        const char *name;
        struct E9Type *type;
        int stack_offset;
    } *locals;
    int num_locals;

    /* Temporaries */
    int num_temps;

    /* IR blocks */
    E9IRBlock **blocks;
    int num_blocks;
    E9IRBlock *entry;

    /* Original function */
    struct E9Function *original;
} E9IRFunc;

/*
 * ============================================================================
 * Decompiler Context
 * ============================================================================
 */

/*
 * Decompiler options
 */
typedef struct E9DecompileOpts {
    bool emit_comments;         /* Add // comments with addresses */
    bool emit_types;            /* Add type annotations */
    bool use_cosmopolitan;      /* Use Cosmopolitan types (int64_t, etc.) */
    bool remove_dead_code;      /* Remove unreachable code */
    bool fold_constants;        /* Constant folding */
    bool inline_small_funcs;    /* Inline single-block functions */
    int indent_width;           /* Indentation (default: 4) */
    const char *header_include; /* Header to include (e.g., "cosmopolitan.h") */
} E9DecompileOpts;

/*
 * Decompiler context
 */
typedef struct E9Decompile {
    struct E9Binary *binary;
    E9DecompileOpts opts;

    /* Type system */
    struct E9Type **types;
    int num_types;

    /* IR functions */
    E9IRFunc **funcs;
    int num_funcs;

    /* Output buffer */
    char *output;
    size_t output_size;
    size_t output_capacity;
} E9Decompile;

/*
 * ============================================================================
 * API
 * ============================================================================
 */

/*
 * Create decompiler context
 */
E9Decompile *e9_decompile_create(struct E9Binary *bin, const E9DecompileOpts *opts);

/*
 * Free decompiler context
 */
void e9_decompile_free(E9Decompile *dc);

/*
 * Lift function to IR
 */
E9IRFunc *e9_decompile_lift(E9Decompile *dc, struct E9Function *func);

/*
 * Structure IR (convert gotos to if/while/for)
 */
int e9_decompile_structure(E9Decompile *dc, E9IRFunc *func);

/*
 * Infer types
 */
int e9_decompile_infer_types(E9Decompile *dc, E9IRFunc *func);

/*
 * Generate C code from IR
 */
char *e9_decompile_emit_c(E9Decompile *dc, E9IRFunc *func);

/*
 * Full decompilation pipeline
 */
char *e9_decompile_function_full(E9Decompile *dc, struct E9Function *func);

/*
 * Decompile entire binary to C source
 */
char *e9_decompile_binary(E9Decompile *dc);

/*
 * Generate Cosmopolitan-compatible header
 */
char *e9_decompile_header(E9Decompile *dc);

/*
 * ============================================================================
 * Cosmopolitan Type Mappings
 * ============================================================================
 *
 * Cosmopolitan uses explicit-width types for portability:
 *   int8_t, int16_t, int32_t, int64_t
 *   uint8_t, uint16_t, uint32_t, uint64_t
 *   intptr_t, uintptr_t, size_t, ssize_t
 *   bool (from stdbool.h)
 *
 * We map register sizes to these types:
 *   8-bit  -> int8_t/uint8_t
 *   16-bit -> int16_t/uint16_t
 *   32-bit -> int32_t/uint32_t
 *   64-bit -> int64_t/uint64_t
 *   pointer -> void * or typed pointer
 */

/*
 * Get Cosmopolitan type string for a size/signedness
 */
const char *e9_type_to_cosmo(int size_bits, bool is_signed, bool is_pointer);

/*
 * ============================================================================
 * IR Construction Helpers
 * ============================================================================
 */

E9IRValue *e9_ir_const(E9Decompile *dc, int64_t value, int size_bits);
E9IRValue *e9_ir_reg(E9Decompile *dc, int reg);
E9IRValue *e9_ir_local(E9Decompile *dc, int index, const char *name);
E9IRValue *e9_ir_temp(E9Decompile *dc, int index);
E9IRValue *e9_ir_binary(E9Decompile *dc, E9IROp op, E9IRValue *left, E9IRValue *right);
E9IRValue *e9_ir_unary(E9Decompile *dc, E9IROp op, E9IRValue *operand);
E9IRValue *e9_ir_load(E9Decompile *dc, E9IRValue *addr, int size);
E9IRValue *e9_ir_store(E9Decompile *dc, E9IRValue *addr, E9IRValue *value, int size);
E9IRValue *e9_ir_call(E9Decompile *dc, E9IRValue *func, E9IRValue **args, int num_args);

#ifdef __cplusplus
}
#endif

#endif /* E9DECOMPILE_H */
