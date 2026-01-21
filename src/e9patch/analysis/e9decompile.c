/*
 * e9decompile.c
 * True C Decompilation Engine Implementation
 *
 * Produces compilable Cosmopolitan C from binary analysis.
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

#include "e9decompile.h"
#include "e9analysis.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>

/*
 * ============================================================================
 * Memory Management
 * ============================================================================
 */

static void *dc_alloc(size_t size)
{
    void *p = calloc(1, size);
    if (!p) {
        fprintf(stderr, "e9decompile: allocation failed (%zu bytes)\n", size);
    }
    return p;
}

static char *dc_strdup(const char *s)
{
    if (!s) return NULL;
    size_t len = strlen(s) + 1;
    char *p = dc_alloc(len);
    if (p) memcpy(p, s, len);
    return p;
}

/*
 * ============================================================================
 * Output Buffer Management
 * ============================================================================
 */

static void emit(E9Decompile *dc, const char *fmt, ...)
{
    va_list args;

    /* Ensure capacity */
    size_t needed = 1024;
    if (dc->output_size + needed > dc->output_capacity) {
        size_t new_cap = dc->output_capacity * 2 + needed;
        char *new_buf = realloc(dc->output, new_cap);
        if (!new_buf) return;
        dc->output = new_buf;
        dc->output_capacity = new_cap;
    }

    va_start(args, fmt);
    int n = vsnprintf(dc->output + dc->output_size,
                      dc->output_capacity - dc->output_size,
                      fmt, args);
    va_end(args);

    if (n > 0) {
        dc->output_size += n;
    }
}

static void emit_indent(E9Decompile *dc, int level)
{
    for (int i = 0; i < level * dc->opts.indent_width; i++) {
        emit(dc, " ");
    }
}

/*
 * ============================================================================
 * Type System
 * ============================================================================
 */

const char *e9_type_to_cosmo(int size_bits, bool is_signed, bool is_pointer)
{
    if (is_pointer) {
        return "void *";
    }

    switch (size_bits) {
        case 8:  return is_signed ? "int8_t" : "uint8_t";
        case 16: return is_signed ? "int16_t" : "uint16_t";
        case 32: return is_signed ? "int32_t" : "uint32_t";
        case 64: return is_signed ? "int64_t" : "uint64_t";
        default: return is_signed ? "int64_t" : "uint64_t";
    }
}

static const char *type_to_c(E9Type *type)
{
    if (!type) return "int64_t";

    switch (type->kind) {
        case E9_TYPE_VOID:   return "void";
        case E9_TYPE_INT8:   return "int8_t";
        case E9_TYPE_INT16:  return "int16_t";
        case E9_TYPE_INT32:  return "int32_t";
        case E9_TYPE_INT64:  return "int64_t";
        case E9_TYPE_UINT8:  return "uint8_t";
        case E9_TYPE_UINT16: return "uint16_t";
        case E9_TYPE_UINT32: return "uint32_t";
        case E9_TYPE_UINT64: return "uint64_t";
        case E9_TYPE_FLOAT:  return "float";
        case E9_TYPE_DOUBLE: return "double";
        case E9_TYPE_POINTER: return "void *";
        default: return "int64_t";
    }
}

/*
 * ============================================================================
 * IR Value Construction
 * ============================================================================
 */

E9IRValue *e9_ir_const(E9Decompile *dc, int64_t value, int size_bits)
{
    (void)dc;
    E9IRValue *v = dc_alloc(sizeof(E9IRValue));
    if (!v) return NULL;
    v->op = E9_IR_CONST;
    v->constant = value;
    /* Type would be set based on size_bits */
    (void)size_bits;
    return v;
}

E9IRValue *e9_ir_reg(E9Decompile *dc, int reg)
{
    (void)dc;
    E9IRValue *v = dc_alloc(sizeof(E9IRValue));
    if (!v) return NULL;
    v->op = E9_IR_REG;
    v->reg = reg;
    return v;
}

E9IRValue *e9_ir_local(E9Decompile *dc, int index, const char *name)
{
    (void)dc;
    E9IRValue *v = dc_alloc(sizeof(E9IRValue));
    if (!v) return NULL;
    v->op = E9_IR_LOCAL;
    v->var.index = index;
    v->var.name = name;
    return v;
}

E9IRValue *e9_ir_temp(E9Decompile *dc, int index)
{
    (void)dc;
    E9IRValue *v = dc_alloc(sizeof(E9IRValue));
    if (!v) return NULL;
    v->op = E9_IR_TEMP;
    v->var.index = index;
    return v;
}

E9IRValue *e9_ir_binary(E9Decompile *dc, E9IROp op, E9IRValue *left, E9IRValue *right)
{
    (void)dc;
    E9IRValue *v = dc_alloc(sizeof(E9IRValue));
    if (!v) return NULL;
    v->op = op;
    v->binary.left = left;
    v->binary.right = right;
    return v;
}

E9IRValue *e9_ir_unary(E9Decompile *dc, E9IROp op, E9IRValue *operand)
{
    (void)dc;
    E9IRValue *v = dc_alloc(sizeof(E9IRValue));
    if (!v) return NULL;
    v->op = op;
    v->unary.operand = operand;
    return v;
}

E9IRValue *e9_ir_load(E9Decompile *dc, E9IRValue *addr, int size)
{
    (void)dc;
    E9IRValue *v = dc_alloc(sizeof(E9IRValue));
    if (!v) return NULL;
    v->op = E9_IR_LOAD;
    v->mem.addr = addr;
    v->mem.size = size;
    return v;
}

E9IRValue *e9_ir_store(E9Decompile *dc, E9IRValue *addr, E9IRValue *value, int size)
{
    (void)dc;
    E9IRValue *v = dc_alloc(sizeof(E9IRValue));
    if (!v) return NULL;
    v->op = E9_IR_STORE;
    v->mem.addr = addr;
    v->mem.size = size;
    /* Store the value in the next pointer of addr for simplicity */
    addr->next = value;
    return v;
}

E9IRValue *e9_ir_call(E9Decompile *dc, E9IRValue *func, E9IRValue **args, int num_args)
{
    (void)dc;
    E9IRValue *v = dc_alloc(sizeof(E9IRValue));
    if (!v) return NULL;
    v->op = E9_IR_CALL;
    v->call.func = func;
    v->call.args = args;
    v->call.num_args = num_args;
    return v;
}

/*
 * ============================================================================
 * IR Value to C Expression
 * ============================================================================
 */

static void emit_value(E9Decompile *dc, E9IRValue *v, int precedence);

static const char *op_to_c(E9IROp op)
{
    switch (op) {
        case E9_IR_ADD: return "+";
        case E9_IR_SUB: return "-";
        case E9_IR_MUL: return "*";
        case E9_IR_DIV: return "/";
        case E9_IR_MOD: return "%%";
        case E9_IR_AND: return "&";
        case E9_IR_OR:  return "|";
        case E9_IR_XOR: return "^";
        case E9_IR_SHL: return "<<";
        case E9_IR_SHR: return ">>";
        case E9_IR_SAR: return ">>";
        case E9_IR_EQ:  return "==";
        case E9_IR_NE:  return "!=";
        case E9_IR_LT:  return "<";
        case E9_IR_LE:  return "<=";
        case E9_IR_GT:  return ">";
        case E9_IR_GE:  return ">=";
        case E9_IR_LTU: return "<";  /* Cast operands to unsigned */
        case E9_IR_LEU: return "<=";
        case E9_IR_GTU: return ">";
        case E9_IR_GEU: return ">=";
        default: return "?";
    }
}

static int op_precedence(E9IROp op)
{
    switch (op) {
        case E9_IR_MUL:
        case E9_IR_DIV:
        case E9_IR_MOD:
            return 3;
        case E9_IR_ADD:
        case E9_IR_SUB:
            return 4;
        case E9_IR_SHL:
        case E9_IR_SHR:
        case E9_IR_SAR:
            return 5;
        case E9_IR_LT:
        case E9_IR_LE:
        case E9_IR_GT:
        case E9_IR_GE:
        case E9_IR_LTU:
        case E9_IR_LEU:
        case E9_IR_GTU:
        case E9_IR_GEU:
            return 6;
        case E9_IR_EQ:
        case E9_IR_NE:
            return 7;
        case E9_IR_AND:
            return 8;
        case E9_IR_XOR:
            return 9;
        case E9_IR_OR:
            return 10;
        default:
            return 15;
    }
}

/* Register names for x86-64 (indexed by register number) */
static const char *x64_reg_names[] = {
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "rip", "rflags",
    "ah", "bh", "ch", "dh"  /* High-byte registers at indices 18-21 */
};
#define X64_REG_COUNT 22

static void emit_value(E9Decompile *dc, E9IRValue *v, int precedence)
{
    if (!v) {
        emit(dc, "0");
        return;
    }

    switch (v->op) {
        case E9_IR_CONST:
            if (v->constant < 0) {
                emit(dc, "(%lld)", (long long)v->constant);
            } else if (v->constant > 0xFFFF) {
                emit(dc, "0x%llx", (unsigned long long)v->constant);
            } else {
                emit(dc, "%lld", (long long)v->constant);
            }
            break;

        case E9_IR_REG:
            if (v->reg >= 0 && v->reg < X64_REG_COUNT) {
                emit(dc, "_%s", x64_reg_names[v->reg]);
            } else {
                emit(dc, "_reg%d", v->reg);
            }
            break;

        case E9_IR_LOCAL:
            if (v->var.name) {
                emit(dc, "%s", v->var.name);
            } else {
                emit(dc, "local_%d", v->var.index);
            }
            break;

        case E9_IR_PARAM:
            if (v->var.name) {
                emit(dc, "%s", v->var.name);
            } else {
                emit(dc, "param_%d", v->var.index);
            }
            break;

        case E9_IR_TEMP:
            emit(dc, "t%d", v->var.index);
            break;

        case E9_IR_GLOBAL:
            if (v->var.name) {
                emit(dc, "%s", v->var.name);
            } else {
                emit(dc, "g_%d", v->var.index);
            }
            break;

        case E9_IR_ADD:
        case E9_IR_SUB:
        case E9_IR_MUL:
        case E9_IR_DIV:
        case E9_IR_MOD:
        case E9_IR_AND:
        case E9_IR_OR:
        case E9_IR_XOR:
        case E9_IR_SHL:
        case E9_IR_SHR:
        case E9_IR_SAR:
        case E9_IR_EQ:
        case E9_IR_NE:
        case E9_IR_LT:
        case E9_IR_LE:
        case E9_IR_GT:
        case E9_IR_GE:
        case E9_IR_LTU:
        case E9_IR_LEU:
        case E9_IR_GTU:
        case E9_IR_GEU:
            {
                int my_prec = op_precedence(v->op);
                bool need_parens = (my_prec >= precedence);

                if (need_parens) emit(dc, "(");
                emit_value(dc, v->binary.left, my_prec);
                emit(dc, " %s ", op_to_c(v->op));
                emit_value(dc, v->binary.right, my_prec);
                if (need_parens) emit(dc, ")");
            }
            break;

        case E9_IR_NEG:
            emit(dc, "-");
            emit_value(dc, v->unary.operand, 2);
            break;

        case E9_IR_NOT:
            emit(dc, "~");
            emit_value(dc, v->unary.operand, 2);
            break;

        case E9_IR_LOAD:
            {
                const char *type = "int64_t";
                switch (v->mem.size) {
                    case 1: type = "int8_t"; break;
                    case 2: type = "int16_t"; break;
                    case 4: type = "int32_t"; break;
                    case 8: type = "int64_t"; break;
                }
                emit(dc, "*(%s *)", type);
                emit_value(dc, v->mem.addr, 2);
            }
            break;

        case E9_IR_ADDRESS:
            emit(dc, "&");
            emit_value(dc, v->unary.operand, 2);
            break;

        case E9_IR_DEREF:
            emit(dc, "*");
            emit_value(dc, v->unary.operand, 2);
            break;

        case E9_IR_CALL:
            emit_value(dc, v->call.func, 15);
            emit(dc, "(");
            for (int i = 0; i < v->call.num_args; i++) {
                if (i > 0) emit(dc, ", ");
                emit_value(dc, v->call.args[i], 15);
            }
            emit(dc, ")");
            break;

        case E9_IR_CAST:
            emit(dc, "(%s)", type_to_c(v->type));
            emit_value(dc, v->unary.operand, 2);
            break;

        default:
            emit(dc, "/* unknown op %d */", v->op);
            break;
    }
}

/*
 * ============================================================================
 * Instruction Lifting to IR
 * ============================================================================
 */

/* x86-64 register mapping */
#define X64_RAX 0
#define X64_RBX 1
#define X64_RCX 2
#define X64_RDX 3
#define X64_RSI 4
#define X64_RDI 5
#define X64_RBP 6
#define X64_RSP 7
#define X64_R8  8
#define X64_R9  9
#define X64_R10 10
#define X64_R11 11
#define X64_R12 12
#define X64_R13 13
#define X64_R14 14
#define X64_R15 15
#define X64_RIP 16
#define X64_RFLAGS 17
/* High-byte registers - distinct from low-byte (al=0, bl=1, etc.) */
#define X64_AH 18
#define X64_BH 19
#define X64_CH 20
#define X64_DH 21

/* 32-bit register names */
static const char *x86_reg32_names[] = {
    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
    "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"
};

/* 16-bit register names */
static const char *x86_reg16_names[] = {
    "ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
    "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"
};

/* 8-bit register names */
static const char *x86_reg8_names[] = {
    "al", "bl", "cl", "dl", "sil", "dil", "bpl", "spl",
    "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"
};

/*
 * Parse a register name and return its index and size in bits
 */
static int parse_register(const char *name, int *size_bits)
{
    if (!name || !*name) return -1;
    
    /* Remove leading % if present (AT&T syntax) */
    if (name[0] == '%') name++;
    
    /* 64-bit registers */
    for (int i = 0; i < 16; i++) {
        if (strcmp(name, x64_reg_names[i]) == 0) {
            if (size_bits) *size_bits = 64;
            return i;
        }
    }
    
    /* 32-bit registers */
    for (int i = 0; i < 16; i++) {
        if (strcmp(name, x86_reg32_names[i]) == 0) {
            if (size_bits) *size_bits = 32;
            return i;
        }
    }
    
    /* 16-bit registers */
    for (int i = 0; i < 16; i++) {
        if (strcmp(name, x86_reg16_names[i]) == 0) {
            if (size_bits) *size_bits = 16;
            return i;
        }
    }
    
    /* 8-bit registers */
    for (int i = 0; i < 16; i++) {
        if (strcmp(name, x86_reg8_names[i]) == 0) {
            if (size_bits) *size_bits = 8;
            return i;
        }
    }
    
    /* Special high byte registers - use distinct indices to avoid ambiguity with al/bl/cl/dl */
    if (strcmp(name, "ah") == 0) { if (size_bits) *size_bits = 8; return X64_AH; }
    if (strcmp(name, "bh") == 0) { if (size_bits) *size_bits = 8; return X64_BH; }
    if (strcmp(name, "ch") == 0) { if (size_bits) *size_bits = 8; return X64_CH; }
    if (strcmp(name, "dh") == 0) { if (size_bits) *size_bits = 8; return X64_DH; }
    
    /* Special registers - rip and rflags */
    if (strcmp(name, "rip") == 0) { if (size_bits) *size_bits = 64; return X64_RIP; }
    if (strcmp(name, "rflags") == 0 || strcmp(name, "eflags") == 0) {
        if (size_bits) *size_bits = 64;
        return X64_RFLAGS;
    }
    
    return -1;
}

/*
 * Parse an operand (register, immediate, or memory reference)
 */
static E9IRValue *parse_operand(E9Decompile *dc, const char *op, int default_size)
{
    if (!op || !*op) return NULL;
    
    /* Skip leading whitespace */
    while (*op == ' ' || *op == '\t') op++;
    
    /* Check for register (parse_register handles AT&T % prefix internally) */
    int size = default_size;
    int reg = parse_register(op, &size);
    if (reg >= 0) {
        return e9_ir_reg(dc, reg);
    }
    
    /* Check for immediate ($ prefix for AT&T, or number for Intel) */
    const char *num = op;
    if (num[0] == '$') num++;  /* AT&T immediate prefix */
    
    /* Use strtoll with base 0 so it handles optional sign and 0x/0 prefixes.
       This correctly parses: 123, -123, 0x1a, -0x1a, 0777, etc. */
    char *endptr = NULL;
    long long imm = strtoll(num, &endptr, 0);
    if (endptr != num && *endptr == '\0') {
        return e9_ir_const(dc, imm, size);
    }
    
    /* Check for memory operand [base + index*scale + disp] or disp(base,index,scale) */
    if (op[0] == '[' || strchr(op, '(') != NULL) {
        /* Memory operand - create a load placeholder.
         * TODO: Implement full memory operand parsing (base, index, scale, displacement).
         * Currently returns a load from a symbolic "MEM" address marker.
         * IR consumers should check for E9_IR_LOAD op and handle appropriately. */
        E9IRValue *mem_marker = dc_alloc(sizeof(E9IRValue));
        if (!mem_marker) return NULL;
        mem_marker->op = E9_IR_GLOBAL;
        mem_marker->var.name = dc_strdup(op);  /* Preserve original for debugging */
        return e9_ir_load(dc, mem_marker, size / 8);
    }
    
    /* Symbol reference */
    E9IRValue *v = dc_alloc(sizeof(E9IRValue));
    if (!v) return NULL;
    v->op = E9_IR_GLOBAL;
    v->var.name = dc_strdup(op);
    return v;
}

/*
 * Check if an E9IRValue represents a register.
 * Returns the register number if it is a register, or -1 otherwise.
 * Note: Reserved for future use in more complex lifting scenarios.
 */
static int ir_value_get_reg(E9IRValue *v) __attribute__((unused));
static int ir_value_get_reg(E9IRValue *v)
{
    if (!v) return -1;
    if (v->op == E9_IR_REG) return v->reg;
    return -1;
}

/*
 * Helper to get the destination for an IR statement.
 * For register operands, returns the register as destination.
 * For memory operands, returns the memory address (for store operations).
 * Returns NULL if the operand cannot be used as a destination.
 */
static E9IRValue *ir_get_dest(E9Decompile *dc, E9IRValue *operand)
{
    (void)dc;  /* Reserved for future use (memory destination handling) */
    if (!operand) return NULL;
    
    if (operand->op == E9_IR_REG) {
        /* Register destination - return as-is */
        return operand;
    }
    
    if (operand->op == E9_IR_LOAD) {
        /* Memory destination - for now, we don't support memory destinations.
         * TODO: Implement store operations for memory destinations.
         * Return NULL to signal that this operation cannot be lifted yet. */
        return NULL;
    }
    
    /* Other operand types (const, global) cannot be destinations */
    return NULL;
}

/*
 * Create an IR statement for a binary operation (add, sub, and, or, xor, etc.)
 */
static E9IRStmt *lift_binary_op(E9Decompile *dc, E9Instruction *insn, E9IROp op)
{
    E9IRStmt *stmt = dc_alloc(sizeof(E9IRStmt));
    if (!stmt) return NULL;
    stmt->addr = insn->address;
    
    char dest[64], src[128];
    if (sscanf(insn->operands, "%63[^,], %127s", dest, src) == 2) {
        E9IRValue *dest_val = parse_operand(dc, dest, 64);
        E9IRValue *src_val = parse_operand(dc, src, 64);
        
        if (dest_val && src_val) {
            /* Check if destination is a valid target (register or memory) */
            E9IRValue *ir_dest = ir_get_dest(dc, dest_val);
            if (!ir_dest) {
                /* Cannot lift: destination is not a register or supported memory.
                 * Leave stmt->dest/value as NULL to signal unhandled instruction. */
                return stmt;
            }
            stmt->dest = ir_dest;
            stmt->value = e9_ir_binary(dc, op, dest_val, src_val);
        }
    }
    
    return stmt;
}

/*
 * Create an IR statement for a shift operation
 */
static E9IRStmt *lift_shift_op(E9Decompile *dc, E9Instruction *insn, E9IROp op)
{
    E9IRStmt *stmt = dc_alloc(sizeof(E9IRStmt));
    if (!stmt) return NULL;
    stmt->addr = insn->address;
    
    char dest[64], shift[32];
    if (sscanf(insn->operands, "%63[^,], %31s", dest, shift) == 2) {
        E9IRValue *dest_val = parse_operand(dc, dest, 64);
        E9IRValue *shift_val = parse_operand(dc, shift, 8);
        
        if (dest_val && shift_val) {
            /* Check if destination is a valid target (register or memory) */
            E9IRValue *ir_dest = ir_get_dest(dc, dest_val);
            if (!ir_dest) {
                /* Cannot lift: destination is not a register or supported memory */
                return stmt;
            }
            stmt->dest = ir_dest;
            stmt->value = e9_ir_binary(dc, op, dest_val, shift_val);
        }
    } else {
        /* Single operand form - shift by 1 */
        E9IRValue *dest_val = parse_operand(dc, insn->operands, 64);
        if (dest_val) {
            /* Check if destination is a valid target */
            E9IRValue *ir_dest = ir_get_dest(dc, dest_val);
            if (!ir_dest) {
                return stmt;
            }
            stmt->dest = ir_dest;
            stmt->value = e9_ir_binary(dc, op, dest_val, e9_ir_const(dc, 1, 8));
        }
    }
    
    return stmt;
}

/*
 * Create an IR statement for a unary operation (not, neg, inc, dec)
 */
static E9IRStmt *lift_unary_op(E9Decompile *dc, E9Instruction *insn, E9IROp op)
{
    E9IRStmt *stmt = dc_alloc(sizeof(E9IRStmt));
    if (!stmt) return NULL;
    stmt->addr = insn->address;
    
    E9IRValue *operand = parse_operand(dc, insn->operands, 64);
    if (operand) {
        /* Check if operand is a valid destination (register or memory) */
        E9IRValue *ir_dest = ir_get_dest(dc, operand);
        if (!ir_dest) {
            /* Cannot lift: operand is not a register or supported memory */
            return stmt;
        }
        stmt->dest = ir_dest;
        
        /* inc/dec are special - add/sub 1 */
        if (op == E9_IR_ADD) {
            stmt->value = e9_ir_binary(dc, E9_IR_ADD, operand, e9_ir_const(dc, 1, 64));
        } else if (op == E9_IR_SUB) {
            stmt->value = e9_ir_binary(dc, E9_IR_SUB, operand, e9_ir_const(dc, 1, 64));
        } else {
            stmt->value = e9_ir_unary(dc, op, operand);
        }
    }
    
    return stmt;
}

static E9IRStmt *lift_instruction(E9Decompile *dc, E9IRFunc *func, E9Instruction *insn)
{
    (void)func;

    E9IRStmt *stmt = dc_alloc(sizeof(E9IRStmt));
    if (!stmt) return NULL;
    stmt->addr = insn->address;

    /* Parse operands to determine operation */
    const char *mnemonic = insn->mnemonic;
    const char *operands = insn->operands;

    /* mov instruction */
    if (strcmp(mnemonic, "mov") == 0 || strcmp(mnemonic, "movq") == 0 ||
        strcmp(mnemonic, "movl") == 0 || strcmp(mnemonic, "movabs") == 0) {
        /* Simple register-to-register or immediate-to-register mov */
        /* Parse dest and source from operands */
        /* Format: "dest, source" */
        char dest[32], src[64];
        if (sscanf(operands, "%31[^,], %63s", dest, src) == 2) {
            E9IRValue *dest_val = NULL;
            E9IRValue *src_val = NULL;

            /* Parse destination */
            for (int i = 0; i < 16; i++) {
                if (strcmp(dest, x64_reg_names[i]) == 0 ||
                    (dest[0] == 'e' && strcmp(dest + 1, x64_reg_names[i] + 1) == 0)) {
                    dest_val = e9_ir_reg(dc, i);
                    break;
                }
            }

            /* Parse source */
            if (src[0] == '0' && src[1] == 'x') {
                src_val = e9_ir_const(dc, strtoll(src, NULL, 16), 64);
            } else if (isdigit(src[0]) || src[0] == '-') {
                src_val = e9_ir_const(dc, strtoll(src, NULL, 10), 64);
            } else {
                for (int i = 0; i < 16; i++) {
                    if (strcmp(src, x64_reg_names[i]) == 0 ||
                        (src[0] == 'e' && strcmp(src + 1, x64_reg_names[i] + 1) == 0)) {
                        src_val = e9_ir_reg(dc, i);
                        break;
                    }
                }
            }

            stmt->dest = dest_val;
            stmt->value = src_val;
        }
    }
    /* add instruction */
    else if (strcmp(mnemonic, "add") == 0 || strcmp(mnemonic, "addq") == 0 ||
             strcmp(mnemonic, "addl") == 0) {
        char dest[32], src[64];
        if (sscanf(operands, "%31[^,], %63s", dest, src) == 2) {
            E9IRValue *dest_val = NULL;
            E9IRValue *src_val = NULL;

            for (int i = 0; i < 16; i++) {
                if (strcmp(dest, x64_reg_names[i]) == 0) {
                    dest_val = e9_ir_reg(dc, i);
                    break;
                }
            }

            if (src[0] == '0' && src[1] == 'x') {
                src_val = e9_ir_const(dc, strtoll(src, NULL, 16), 64);
            } else if (isdigit(src[0]) || src[0] == '-') {
                src_val = e9_ir_const(dc, strtoll(src, NULL, 10), 64);
            } else {
                for (int i = 0; i < 16; i++) {
                    if (strcmp(src, x64_reg_names[i]) == 0) {
                        src_val = e9_ir_reg(dc, i);
                        break;
                    }
                }
            }

            if (dest_val && src_val) {
                stmt->dest = e9_ir_reg(dc, dest_val->reg);
                stmt->value = e9_ir_binary(dc, E9_IR_ADD, dest_val, src_val);
            }
        }
    }
    /* sub instruction */
    else if (strcmp(mnemonic, "sub") == 0 || strcmp(mnemonic, "subq") == 0 ||
             strcmp(mnemonic, "subl") == 0) {
        char dest[32], src[64];
        if (sscanf(operands, "%31[^,], %63s", dest, src) == 2) {
            E9IRValue *dest_val = NULL;
            E9IRValue *src_val = NULL;

            for (int i = 0; i < 16; i++) {
                if (strcmp(dest, x64_reg_names[i]) == 0) {
                    dest_val = e9_ir_reg(dc, i);
                    break;
                }
            }

            if (src[0] == '0' && src[1] == 'x') {
                src_val = e9_ir_const(dc, strtoll(src, NULL, 16), 64);
            } else if (isdigit(src[0]) || src[0] == '-') {
                src_val = e9_ir_const(dc, strtoll(src, NULL, 10), 64);
            }

            if (dest_val && src_val) {
                stmt->dest = e9_ir_reg(dc, dest_val->reg);
                stmt->value = e9_ir_binary(dc, E9_IR_SUB, dest_val, src_val);
            }
        }
    }
    /* xor with self = zero */
    else if (strcmp(mnemonic, "xor") == 0 || strcmp(mnemonic, "xorl") == 0) {
        char dest[32], src[32];
        if (sscanf(operands, "%31[^,], %31s", dest, src) == 2) {
            if (strcmp(dest, src) == 0) {
                /* xor reg, reg = 0 */
                for (int i = 0; i < 16; i++) {
                    if (strcmp(dest, x64_reg_names[i]) == 0 ||
                        (dest[0] == 'e' && strcmp(dest + 1, x64_reg_names[i] + 1) == 0)) {
                        stmt->dest = e9_ir_reg(dc, i);
                        stmt->value = e9_ir_const(dc, 0, 64);
                        break;
                    }
                }
            }
        }
    }
    /* call */
    else if (strcmp(mnemonic, "call") == 0 || strcmp(mnemonic, "callq") == 0) {
        E9IRValue *target = NULL;
        if (insn->target) {
            /* Direct call - create a constant for the address */
            target = e9_ir_const(dc, insn->target, 64);
        } else {
            /* Indirect call - parse the operand */
            target = e9_ir_reg(dc, X64_RAX);  /* Simplified */
        }
        stmt->dest = e9_ir_reg(dc, X64_RAX);  /* Return value in rax */
        stmt->value = e9_ir_call(dc, target, NULL, 0);
    }
    /* ret */
    else if (strcmp(mnemonic, "ret") == 0 || strcmp(mnemonic, "retq") == 0) {
        E9IRValue *ret_val = dc_alloc(sizeof(E9IRValue));
        if (ret_val) {
            ret_val->op = E9_IR_RET;
            ret_val->unary.operand = e9_ir_reg(dc, X64_RAX);
        }
        stmt->value = ret_val;
    }
    /* Default: comment the instruction */
    else {
        /* Create a placeholder */
        stmt->dest = NULL;
        stmt->value = NULL;
    }

    return stmt;
}

/*
 * ============================================================================
 * Main Decompilation Pipeline
 * ============================================================================
 */

E9Decompile *e9_decompile_create(E9Binary *bin, const E9DecompileOpts *opts)
{
    E9Decompile *dc = dc_alloc(sizeof(E9Decompile));
    if (!dc) return NULL;

    dc->binary = bin;

    if (opts) {
        dc->opts = *opts;
    } else {
        /* Default options */
        dc->opts.emit_comments = true;
        dc->opts.emit_types = true;
        dc->opts.use_cosmopolitan = true;
        dc->opts.remove_dead_code = true;
        dc->opts.fold_constants = true;
        dc->opts.indent_width = 4;
        dc->opts.header_include = "cosmopolitan.h";
    }

    dc->output_capacity = 65536;
    dc->output = dc_alloc(dc->output_capacity);

    return dc;
}

void e9_decompile_free(E9Decompile *dc)
{
    if (!dc) return;

    /* Free IR functions */
    for (int i = 0; i < dc->num_funcs; i++) {
        E9IRFunc *func = dc->funcs[i];
        if (!func) continue;

        /* Free blocks */
        for (int j = 0; j < func->num_blocks; j++) {
            E9IRBlock *block = func->blocks[j];
            if (!block) continue;

            /* Free statements */
            E9IRStmt *stmt = block->first_stmt;
            while (stmt) {
                E9IRStmt *next = stmt->next;
                /* Note: IR values are not freed individually for simplicity */
                free(stmt);
                stmt = next;
            }
            free(block);
        }
        free(func->blocks);
        free(func->params);
        free(func->locals);
        free(func);
    }
    free(dc->funcs);

    free(dc->types);
    free(dc->output);
    free(dc);
}

E9IRFunc *e9_decompile_lift(E9Decompile *dc, E9Function *func)
{
    if (!dc || !func || !func->cfg) return NULL;

    E9IRFunc *ir_func = dc_alloc(sizeof(E9IRFunc));
    if (!ir_func) return NULL;

    ir_func->name = func->name ? dc_strdup(func->name) : dc_strdup("sub");
    ir_func->original = func;

    /* Allocate blocks */
    ir_func->num_blocks = func->cfg->num_blocks;
    ir_func->blocks = dc_alloc(ir_func->num_blocks * sizeof(E9IRBlock *));
    if (!ir_func->blocks) {
        free(ir_func);
        return NULL;
    }

    /* Lift each basic block */
    for (int i = 0; i < ir_func->num_blocks; i++) {
        E9BasicBlock *bb = func->cfg->blocks[i];
        E9IRBlock *ir_block = dc_alloc(sizeof(E9IRBlock));
        if (!ir_block) continue;

        ir_block->id = i;
        ir_block->original = bb;
        ir_func->blocks[i] = ir_block;

        if (bb == func->cfg->entry) {
            ir_func->entry = ir_block;
        }

        /* Lift instructions to IR statements */
        E9Instruction *insn = bb->first;
        while (insn) {
            E9IRStmt *stmt = lift_instruction(dc, ir_func, insn);
            if (stmt) {
                if (!ir_block->first_stmt) {
                    ir_block->first_stmt = stmt;
                } else {
                    ir_block->last_stmt->next = stmt;
                }
                ir_block->last_stmt = stmt;
                ir_block->num_stmts++;
            }
            insn = insn->next;
        }
    }

    return ir_func;
}

int e9_decompile_structure(E9Decompile *dc, E9IRFunc *func)
{
    if (!dc || !func) return -1;

    /* TODO: Implement control flow structuring
     * This would convert the IR from goto-based to structured form.
     * For now, we emit goto-based code which is valid C.
     */

    /* Mark all blocks as sequential by default */
    for (int i = 0; i < func->num_blocks; i++) {
        if (func->blocks[i]) {
            func->blocks[i]->structured.type = E9_STRUCT_SEQ;
        }
    }

    return 0;
}

int e9_decompile_infer_types(E9Decompile *dc, E9IRFunc *func)
{
    if (!dc || !func) return -1;

    /* TODO: Implement type inference
     * This would analyze usage patterns to determine types.
     * For now, we use int64_t as the default type.
     */

    return 0;
}

char *e9_decompile_emit_c(E9Decompile *dc, E9IRFunc *func)
{
    if (!dc || !func) return NULL;

    /* Reset output buffer */
    dc->output_size = 0;

    /* Function signature */
    if (dc->opts.emit_comments) {
        emit(dc, "/* Function: %s */\n", func->name);
        if (func->original) {
            emit(dc, "/* Address: 0x%lx */\n", func->original->address);
        }
    }

    const char *ret_type = "int64_t";
    if (func->return_type) {
        ret_type = type_to_c(func->return_type);
    }

    emit(dc, "%s %s(", ret_type, func->name);

    if (func->num_params == 0) {
        emit(dc, "void");
    } else {
        for (int i = 0; i < func->num_params; i++) {
            if (i > 0) emit(dc, ", ");
            const char *ptype = func->params[i].type ?
                type_to_c(func->params[i].type) : "int64_t";
            const char *pname = func->params[i].name ?
                func->params[i].name : "arg";
            emit(dc, "%s %s%d", ptype, pname, i);
        }
    }
    emit(dc, ")\n{\n");

    /* Local variable declarations */
    emit_indent(dc, 1);
    emit(dc, "/* Register-mapped variables */\n");
    emit_indent(dc, 1);
    emit(dc, "int64_t _rax = 0, _rbx = 0, _rcx = 0, _rdx = 0;\n");
    emit_indent(dc, 1);
    emit(dc, "int64_t _rsi = 0, _rdi = 0, _rbp = 0;\n");
    emit_indent(dc, 1);
    emit(dc, "int64_t _r8 = 0, _r9 = 0, _r10 = 0, _r11 = 0;\n");
    emit_indent(dc, 1);
    emit(dc, "int64_t _r12 = 0, _r13 = 0, _r14 = 0, _r15 = 0;\n\n");

    /* Emit each block */
    for (int i = 0; i < func->num_blocks; i++) {
        E9IRBlock *block = func->blocks[i];
        if (!block) continue;

        /* Block label */
        emit(dc, "block_%d:", i);
        if (dc->opts.emit_comments && block->original) {
            emit(dc, " /* 0x%lx */", block->original->start_addr);
        }
        emit(dc, "\n");

        /* Emit statements */
        E9IRStmt *stmt = block->first_stmt;
        while (stmt) {
            emit_indent(dc, 1);

            if (stmt->dest && stmt->value) {
                emit_value(dc, stmt->dest, 15);
                emit(dc, " = ");
                emit_value(dc, stmt->value, 15);
                emit(dc, ";");
            } else if (stmt->value && stmt->value->op == E9_IR_RET) {
                emit(dc, "return _rax;");
            } else if (stmt->value) {
                emit_value(dc, stmt->value, 15);
                emit(dc, ";");
            } else {
                emit(dc, "/* unlifted */");
            }

            if (dc->opts.emit_comments && stmt->addr) {
                emit(dc, " /* 0x%lx */", stmt->addr);
            }
            emit(dc, "\n");

            stmt = stmt->next;
        }

        emit(dc, "\n");
    }

    emit(dc, "}\n");

    return dc_strdup(dc->output);
}

char *e9_decompile_function_full(E9Decompile *dc, E9Function *func)
{
    if (!dc || !func) return NULL;

    /* Ensure CFG is built */
    if (!func->cfg) {
        func->cfg = e9_cfg_build(dc->binary, func);
        if (!func->cfg) return NULL;
    }

    /* Lift to IR */
    E9IRFunc *ir_func = e9_decompile_lift(dc, func);
    if (!ir_func) return NULL;

    /* Structure control flow */
    e9_decompile_structure(dc, ir_func);

    /* Infer types */
    e9_decompile_infer_types(dc, ir_func);

    /* Generate C */
    char *result = e9_decompile_emit_c(dc, ir_func);

    /* Store in function */
    free(func->decompiled_c);
    func->decompiled_c = result ? dc_strdup(result) : NULL;

    return result;
}

char *e9_decompile_header(E9Decompile *dc)
{
    if (!dc) return NULL;

    dc->output_size = 0;

    emit(dc, "/*\n");
    emit(dc, " * Decompiled header - generated by E9Studio\n");
    emit(dc, " * Compile with: cosmocc -o output this_file.c\n");
    emit(dc, " */\n\n");

    if (dc->opts.header_include) {
        emit(dc, "#include <%s>\n\n", dc->opts.header_include);
    } else {
        emit(dc, "#include <stdint.h>\n");
        emit(dc, "#include <stdbool.h>\n");
        emit(dc, "#include <stddef.h>\n\n");
    }

    /* Function prototypes */
    if (dc->binary) {
        E9Function *func = dc->binary->functions;
        while (func) {
            const char *name = func->name ? func->name : "sub";
            emit(dc, "int64_t %s(void);\n", name);
            func = func->next;
        }
    }

    emit(dc, "\n");

    return dc_strdup(dc->output);
}

char *e9_decompile_binary(E9Decompile *dc)
{
    if (!dc || !dc->binary) return NULL;

    dc->output_size = 0;

    /* Header */
    char *header = e9_decompile_header(dc);
    if (header) {
        emit(dc, "%s", header);
        free(header);
    }

    /* Decompile each function */
    E9Function *func = dc->binary->functions;
    while (func) {
        char *c_code = e9_decompile_function_full(dc, func);
        if (c_code) {
            emit(dc, "\n%s\n", c_code);
            free(c_code);
        }
        func = func->next;
    }

    return dc_strdup(dc->output);
}
