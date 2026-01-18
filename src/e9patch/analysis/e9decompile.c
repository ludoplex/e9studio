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

/* Register names for x86-64 */
static const char *x64_reg_names[] = {
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "rip", "rflags"
};

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
            if (v->reg >= 0 && v->reg < 18) {
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
