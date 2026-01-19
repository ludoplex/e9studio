/*
 * e9func_sigs.c
 * Function Signature Matching Implementation
 *
 * Automatic function identification in stripped binaries using
 * pattern matching, prologue analysis, and library signature database.
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

#include "e9func_sigs.h"
#include "e9analysis.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/*
 * ============================================================================
 * Built-in Function Signatures
 * ============================================================================
 */

/* x86-64 function prologues */
static const uint8_t X64_PROLOGUE_1[] = { 0x55, 0x48, 0x89, 0xE5 };  /* push rbp; mov rbp, rsp */
static const uint8_t X64_PROLOGUE_2[] = { 0x55, 0x48, 0x8B, 0xEC };  /* push rbp; mov rbp, rsp (alt) */
static const uint8_t X64_PROLOGUE_3[] = { 0x41, 0x57 };              /* push r15 */
static const uint8_t X64_PROLOGUE_4[] = { 0x53 };                     /* push rbx */

/* x86-64 function epilogues */
static const uint8_t X64_EPILOGUE_1[] = { 0x5D, 0xC3 };              /* pop rbp; ret */
static const uint8_t X64_EPILOGUE_2[] = { 0xC9, 0xC3 };              /* leave; ret */

/* AArch64 function prologues */
static const uint8_t A64_PROLOGUE_1[] = { 0xFD, 0x7B, 0xBF, 0xA9 };  /* stp x29, x30, [sp, #-16]! */

/* AArch64 function epilogues */
static const uint8_t A64_EPILOGUE_1[] = { 0xFD, 0x7B, 0xC1, 0xA8, 0xC0, 0x03, 0x5F, 0xD6 };  /* ldp x29, x30, [sp], #16; ret */

/* Mask for wildcard matching */
static const uint8_t MASK_EXACT_4[] = { 0xFF, 0xFF, 0xFF, 0xFF };
static const uint8_t MASK_EXACT_2[] = { 0xFF, 0xFF };
static const uint8_t MASK_EXACT_1[] = { 0xFF };
static const uint8_t MASK_EXACT_8[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

/*
 * Standard C Library Function Signatures
 */
const E9FuncSig E9_SIGS_LIBC[] = {
    /* String functions */
    {
        .name = "strlen",
        .lib = "libc",
        .type = E9_FSIG_PROLOGUE,
        .arch = E9_FSIG_ARCH_X64,
        .pattern = (const uint8_t[]){ 0x31, 0xC0 },  /* xor eax, eax - common start */
        .mask = MASK_EXACT_2,
        .pattern_len = 2,
        .offset = 0,
        .min_size = 8,
        .max_size = 200,
        .ret_type = "size_t",
        .param_types = "const char *",
        .flags = E9_FSIG_FLAG_LEAF,
    },
    {
        .name = "memcpy",
        .lib = "libc",
        .type = E9_FSIG_PROLOGUE,
        .arch = E9_FSIG_ARCH_X64,
        .pattern = X64_PROLOGUE_1,
        .mask = MASK_EXACT_4,
        .pattern_len = 4,
        .offset = 0,
        .min_size = 16,
        .max_size = 500,
        .ret_type = "void *",
        .param_types = "void *, const void *, size_t",
        .flags = 0,
    },
    {
        .name = "memset",
        .lib = "libc",
        .type = E9_FSIG_PROLOGUE,
        .arch = E9_FSIG_ARCH_X64,
        .pattern = X64_PROLOGUE_1,
        .mask = MASK_EXACT_4,
        .pattern_len = 4,
        .offset = 0,
        .min_size = 16,
        .max_size = 300,
        .ret_type = "void *",
        .param_types = "void *, int, size_t",
        .flags = 0,
    },
    /* Memory allocation */
    {
        .name = "malloc",
        .lib = "libc",
        .type = E9_FSIG_PROLOGUE,
        .arch = E9_FSIG_ARCH_X64,
        .pattern = X64_PROLOGUE_1,
        .mask = MASK_EXACT_4,
        .pattern_len = 4,
        .offset = 0,
        .min_size = 32,
        .max_size = 2000,
        .ret_type = "void *",
        .param_types = "size_t",
        .flags = 0,
    },
    {
        .name = "free",
        .lib = "libc",
        .type = E9_FSIG_PROLOGUE,
        .arch = E9_FSIG_ARCH_X64,
        .pattern = X64_PROLOGUE_1,
        .mask = MASK_EXACT_4,
        .pattern_len = 4,
        .offset = 0,
        .min_size = 16,
        .max_size = 1000,
        .ret_type = "void",
        .param_types = "void *",
        .flags = 0,
    },
    /* I/O functions */
    {
        .name = "printf",
        .lib = "libc",
        .type = E9_FSIG_PROLOGUE,
        .arch = E9_FSIG_ARCH_X64,
        .pattern = X64_PROLOGUE_1,
        .mask = MASK_EXACT_4,
        .pattern_len = 4,
        .offset = 0,
        .min_size = 32,
        .max_size = 2000,
        .ret_type = "int",
        .param_types = "const char *, ...",
        .flags = E9_FSIG_FLAG_VARIADIC,
    },
};
const size_t E9_SIGS_LIBC_COUNT = sizeof(E9_SIGS_LIBC) / sizeof(E9_SIGS_LIBC[0]);

/*
 * Compiler Intrinsic Signatures
 */
const E9FuncSig E9_SIGS_COMPILER[] = {
    /* Stack protection */
    {
        .name = "__stack_chk_fail",
        .lib = "compiler",
        .type = E9_FSIG_BODY,
        .arch = E9_FSIG_ARCH_X64,
        .pattern = (const uint8_t[]){ 0xE8 },  /* call instruction */
        .mask = MASK_EXACT_1,
        .pattern_len = 1,
        .offset = 0,
        .min_size = 4,
        .max_size = 64,
        .ret_type = "void",
        .param_types = "",
        .flags = E9_FSIG_FLAG_NORETURN,
    },
    /* Integer division helpers */
    {
        .name = "__divdi3",
        .lib = "compiler",
        .type = E9_FSIG_PROLOGUE,
        .arch = E9_FSIG_ARCH_X64,
        .pattern = X64_PROLOGUE_1,
        .mask = MASK_EXACT_4,
        .pattern_len = 4,
        .offset = 0,
        .min_size = 16,
        .max_size = 256,
        .ret_type = "int64_t",
        .param_types = "int64_t, int64_t",
        .flags = 0,
    },
};
const size_t E9_SIGS_COMPILER_COUNT = sizeof(E9_SIGS_COMPILER) / sizeof(E9_SIGS_COMPILER[0]);

/*
 * C++ Runtime Signatures
 */
const E9FuncSig E9_SIGS_CXXRT[] = {
    {
        .name = "_Znwm",  /* operator new(size_t) */
        .lib = "cxx",
        .type = E9_FSIG_PROLOGUE,
        .arch = E9_FSIG_ARCH_X64,
        .pattern = X64_PROLOGUE_1,
        .mask = MASK_EXACT_4,
        .pattern_len = 4,
        .offset = 0,
        .min_size = 16,
        .max_size = 256,
        .ret_type = "void *",
        .param_types = "size_t",
        .flags = 0,
    },
    {
        .name = "_ZdlPv",  /* operator delete(void*) */
        .lib = "cxx",
        .type = E9_FSIG_PROLOGUE,
        .arch = E9_FSIG_ARCH_X64,
        .pattern = X64_PROLOGUE_1,
        .mask = MASK_EXACT_4,
        .pattern_len = 4,
        .offset = 0,
        .min_size = 8,
        .max_size = 256,
        .ret_type = "void",
        .param_types = "void *",
        .flags = 0,
    },
    {
        .name = "__cxa_throw",
        .lib = "cxx",
        .type = E9_FSIG_PROLOGUE,
        .arch = E9_FSIG_ARCH_X64,
        .pattern = X64_PROLOGUE_1,
        .mask = MASK_EXACT_4,
        .pattern_len = 4,
        .offset = 0,
        .min_size = 32,
        .max_size = 512,
        .ret_type = "void",
        .param_types = "void *, void *, void (*)(void *)",
        .flags = E9_FSIG_FLAG_NORETURN,
    },
};
const size_t E9_SIGS_CXXRT_COUNT = sizeof(E9_SIGS_CXXRT) / sizeof(E9_SIGS_CXXRT[0]);

/*
 * Crypto Function Signatures
 */
const E9FuncSig E9_SIGS_CRYPTO[] = {
    {
        .name = "SHA256_Init",
        .lib = "crypto",
        .type = E9_FSIG_CONSTANT,
        .arch = E9_FSIG_ARCH_ANY,
        .pattern = (const uint8_t[]){ 0x67, 0xE6, 0x09, 0x6A },  /* SHA256 initial H0 */
        .mask = MASK_EXACT_4,
        .pattern_len = 4,
        .offset = -1,  /* Search within function */
        .min_size = 16,
        .max_size = 256,
        .ret_type = "int",
        .param_types = "SHA256_CTX *",
        .flags = 0,
    },
    {
        .name = "AES_encrypt",
        .lib = "crypto",
        .type = E9_FSIG_CONSTANT,
        .arch = E9_FSIG_ARCH_ANY,
        .pattern = (const uint8_t[]){ 0x63, 0x7C, 0x77, 0x7B },  /* AES S-box start */
        .mask = MASK_EXACT_4,
        .pattern_len = 4,
        .offset = -1,
        .min_size = 64,
        .max_size = 4096,
        .ret_type = "void",
        .param_types = "const unsigned char *, unsigned char *, const AES_KEY *",
        .flags = 0,
    },
};
const size_t E9_SIGS_CRYPTO_COUNT = sizeof(E9_SIGS_CRYPTO) / sizeof(E9_SIGS_CRYPTO[0]);

/*
 * Syscall Wrapper Signatures
 */
const E9FuncSig E9_SIGS_SYSCALL[] = {
    {
        .name = "__syscall_read",
        .lib = "syscall",
        .type = E9_FSIG_SYSCALL,
        .arch = E9_FSIG_ARCH_X64,
        .pattern = (const uint8_t[]){ 0x0F, 0x05 },  /* syscall instruction */
        .mask = MASK_EXACT_2,
        .pattern_len = 2,
        .offset = -1,
        .syscall_nr = 0,  /* SYS_read */
        .min_size = 8,
        .max_size = 64,
        .ret_type = "ssize_t",
        .param_types = "int, void *, size_t",
        .flags = 0,
    },
    {
        .name = "__syscall_write",
        .lib = "syscall",
        .type = E9_FSIG_SYSCALL,
        .arch = E9_FSIG_ARCH_X64,
        .pattern = (const uint8_t[]){ 0x0F, 0x05 },
        .mask = MASK_EXACT_2,
        .pattern_len = 2,
        .offset = -1,
        .syscall_nr = 1,  /* SYS_write */
        .min_size = 8,
        .max_size = 64,
        .ret_type = "ssize_t",
        .param_types = "int, const void *, size_t",
        .flags = 0,
    },
    {
        .name = "__syscall_open",
        .lib = "syscall",
        .type = E9_FSIG_SYSCALL,
        .arch = E9_FSIG_ARCH_X64,
        .pattern = (const uint8_t[]){ 0x0F, 0x05 },
        .mask = MASK_EXACT_2,
        .pattern_len = 2,
        .offset = -1,
        .syscall_nr = 2,  /* SYS_open */
        .min_size = 8,
        .max_size = 64,
        .ret_type = "int",
        .param_types = "const char *, int, ...",
        .flags = E9_FSIG_FLAG_VARIADIC,
    },
    {
        .name = "__syscall_exit",
        .lib = "syscall",
        .type = E9_FSIG_SYSCALL,
        .arch = E9_FSIG_ARCH_X64,
        .pattern = (const uint8_t[]){ 0x0F, 0x05 },
        .mask = MASK_EXACT_2,
        .pattern_len = 2,
        .offset = -1,
        .syscall_nr = 60,  /* SYS_exit */
        .min_size = 8,
        .max_size = 32,
        .ret_type = "void",
        .param_types = "int",
        .flags = E9_FSIG_FLAG_NORETURN,
    },
};
const size_t E9_SIGS_SYSCALL_COUNT = sizeof(E9_SIGS_SYSCALL) / sizeof(E9_SIGS_SYSCALL[0]);

/*
 * ============================================================================
 * Signature Database Implementation
 * ============================================================================
 */

struct E9FuncSigDB {
    E9FuncSig *sigs;
    size_t count;
    size_t capacity;
};

E9FuncSigDB *e9_fsigdb_create(void)
{
    E9FuncSigDB *db = calloc(1, sizeof(E9FuncSigDB));
    if (!db) return NULL;

    db->capacity = 512;
    db->sigs = calloc(db->capacity, sizeof(E9FuncSig));
    if (!db->sigs) {
        free(db);
        return NULL;
    }

    /* Load built-in signatures */
    for (size_t i = 0; i < E9_SIGS_LIBC_COUNT; i++) {
        e9_fsigdb_add(db, &E9_SIGS_LIBC[i]);
    }
    for (size_t i = 0; i < E9_SIGS_COMPILER_COUNT; i++) {
        e9_fsigdb_add(db, &E9_SIGS_COMPILER[i]);
    }
    for (size_t i = 0; i < E9_SIGS_CXXRT_COUNT; i++) {
        e9_fsigdb_add(db, &E9_SIGS_CXXRT[i]);
    }
    for (size_t i = 0; i < E9_SIGS_CRYPTO_COUNT; i++) {
        e9_fsigdb_add(db, &E9_SIGS_CRYPTO[i]);
    }
    for (size_t i = 0; i < E9_SIGS_SYSCALL_COUNT; i++) {
        e9_fsigdb_add(db, &E9_SIGS_SYSCALL[i]);
    }

    return db;
}

void e9_fsigdb_free(E9FuncSigDB *db)
{
    if (!db) return;
    free(db->sigs);
    free(db);
}

int e9_fsigdb_add(E9FuncSigDB *db, const E9FuncSig *sig)
{
    if (!db || !sig) return -1;

    if (db->count >= db->capacity) {
        size_t new_cap = db->capacity * 2;
        E9FuncSig *new_sigs = realloc(db->sigs, new_cap * sizeof(E9FuncSig));
        if (!new_sigs) return -1;
        db->sigs = new_sigs;
        db->capacity = new_cap;
    }

    db->sigs[db->count++] = *sig;
    return 0;
}

size_t e9_fsigdb_count(const E9FuncSigDB *db)
{
    return db ? db->count : 0;
}

/*
 * ============================================================================
 * Pattern Matching
 * ============================================================================
 */

static bool match_pattern(const uint8_t *data, size_t size,
                          const uint8_t *pattern, const uint8_t *mask,
                          size_t pattern_len)
{
    if (size < pattern_len) return false;

    for (size_t i = 0; i < pattern_len; i++) {
        if ((data[i] & mask[i]) != (pattern[i] & mask[i])) {
            return false;
        }
    }
    return true;
}

static bool search_pattern(const uint8_t *data, size_t size,
                           const uint8_t *pattern, const uint8_t *mask,
                           size_t pattern_len, size_t *found_offset)
{
    if (size < pattern_len) return false;

    for (size_t i = 0; i <= size - pattern_len; i++) {
        if (match_pattern(data + i, size - i, pattern, mask, pattern_len)) {
            if (found_offset) *found_offset = i;
            return true;
        }
    }
    return false;
}

static int detect_syscall_number(const uint8_t *code, size_t size, int arch)
{
    if (arch != E9_FSIG_ARCH_X64) return -1;

    /* Look for: mov eax, <nr> followed by syscall */
    for (size_t i = 0; i + 6 < size; i++) {
        /* Check for syscall instruction */
        if (code[i] == 0x0F && code[i + 1] == 0x05) {
            /* Search backwards for mov eax, imm32 */
            for (int j = (int)i - 1; j >= 0 && j > (int)i - 20; j--) {
                if (code[j] == 0xB8) {  /* mov eax, imm32 */
                    return *(int32_t *)(code + j + 1);
                }
                /* mov edi, imm32 (for rax = syscall nr on some wrappers) */
                if (j > 0 && code[j - 1] == 0x48 && code[j] == 0xC7 &&
                    code[j + 1] == 0xC0) {
                    return *(int32_t *)(code + j + 2);
                }
            }
        }
    }
    return -1;
}

/*
 * ============================================================================
 * Matching Functions
 * ============================================================================
 */

E9FuncSigMatch *e9_fsig_match(E9FuncSigDB *db, const uint8_t *code,
                               size_t code_size, uint64_t base_addr,
                               uint64_t func_addr, int arch,
                               uint32_t *num_matches)
{
    if (!db || !code || !num_matches) return NULL;

    *num_matches = 0;

    /* Calculate offset into code buffer */
    if (func_addr < base_addr) return NULL;
    size_t func_offset = func_addr - base_addr;
    if (func_offset >= code_size) return NULL;

    const uint8_t *func_code = code + func_offset;
    size_t remaining = code_size - func_offset;

    /* Allocate result array */
    size_t max_matches = 16;
    E9FuncSigMatch *matches = calloc(max_matches, sizeof(E9FuncSigMatch));
    if (!matches) return NULL;

    /* Try each signature */
    for (size_t i = 0; i < db->count; i++) {
        const E9FuncSig *sig = &db->sigs[i];

        /* Architecture filter */
        if (sig->arch != E9_FSIG_ARCH_ANY && sig->arch != arch) {
            continue;
        }

        /* Check pattern */
        bool matched = false;
        E9ConfLevel confidence = E9_CONF_LOW;

        switch (sig->type) {
            case E9_FSIG_PROLOGUE:
                if (sig->offset == 0) {
                    matched = match_pattern(func_code, remaining,
                                            sig->pattern, sig->mask,
                                            sig->pattern_len);
                }
                break;

            case E9_FSIG_EPILOGUE:
                /* Search for epilogue pattern */
                matched = search_pattern(func_code, remaining,
                                         sig->pattern, sig->mask,
                                         sig->pattern_len, NULL);
                break;

            case E9_FSIG_BODY:
            case E9_FSIG_CONSTANT:
                matched = search_pattern(func_code, remaining,
                                         sig->pattern, sig->mask,
                                         sig->pattern_len, NULL);
                if (matched && sig->type == E9_FSIG_CONSTANT) {
                    confidence = E9_CONF_MEDIUM;  /* Constant match is more reliable */
                }
                break;

            case E9_FSIG_SYSCALL:
                {
                    int nr = detect_syscall_number(func_code, remaining, arch);
                    if (nr == sig->syscall_nr) {
                        matched = true;
                        confidence = E9_CONF_HIGH;  /* Syscall number is very reliable */
                    }
                }
                break;

            case E9_FSIG_STRING_REF:
                /* TODO: Implement string reference matching */
                break;
        }

        if (matched) {
            /* Grow array if needed */
            if (*num_matches >= max_matches) {
                max_matches *= 2;
                E9FuncSigMatch *new_matches = realloc(matches,
                    max_matches * sizeof(E9FuncSigMatch));
                if (!new_matches) break;
                matches = new_matches;
            }

            matches[*num_matches].sig = sig;
            matches[*num_matches].address = func_addr;
            matches[*num_matches].confidence = confidence;
            matches[*num_matches].score = confidence * 100;
            (*num_matches)++;
        }
    }

    /* Sort by confidence (descending) */
    for (uint32_t i = 0; i < *num_matches - 1; i++) {
        for (uint32_t j = i + 1; j < *num_matches; j++) {
            if (matches[j].confidence > matches[i].confidence) {
                E9FuncSigMatch tmp = matches[i];
                matches[i] = matches[j];
                matches[j] = tmp;
            }
        }
    }

    return matches;
}

/*
 * ============================================================================
 * Binary Integration
 * ============================================================================
 */

int e9_fsig_analyze_binary(E9FuncSigDB *db, E9Binary *bin)
{
    if (!db || !bin) return -1;

    int arch;
    switch (bin->arch) {
        case E9_ARCH_X86_64:  arch = E9_FSIG_ARCH_X64; break;
        case E9_ARCH_AARCH64: arch = E9_FSIG_ARCH_AARCH64; break;
        default: return -1;
    }

    int injected = 0;

    /* For each discovered function without a symbol */
    E9Function *func = bin->functions;
    while (func) {
        /* Skip if already has a real name (not auto-generated) */
        if (func->name && strncmp(func->name, "FUN_", 4) != 0) {
            func = func->next;
            continue;
        }

        /* Try to match signature */
        uint32_t num_matches = 0;
        E9FuncSigMatch *matches = e9_fsig_match(db, bin->data, bin->size,
                                                  bin->base_address,
                                                  func->address, arch,
                                                  &num_matches);

        if (matches && num_matches > 0 && matches[0].confidence >= E9_CONF_MEDIUM) {
            /* Use the best match */
            const E9FuncSig *sig = matches[0].sig;

            /* Update function name */
            free(func->name);
            func->name = strdup(sig->name);

            /* Add or update symbol */
            E9Symbol *sym = e9_symbol_at(bin, func->address);
            if (!sym) {
                sym = e9_symbol_add(bin, sig->name, func->address, E9_SYM_FUNCTION);
            } else {
                free(sym->name);
                sym->name = strdup(sig->name);
            }

            /* Set function flags based on signature */
            if (sig->flags & E9_FSIG_FLAG_NORETURN) {
                func->is_noreturn = true;
            }
            if (sig->flags & E9_FSIG_FLAG_LEAF) {
                func->is_leaf = true;
            }
            if (sig->flags & E9_FSIG_FLAG_VARIADIC) {
                func->is_variadic = true;
            }

            /* Generate function signature string */
            if (sig->ret_type && sig->param_types) {
                char sig_buf[256];
                snprintf(sig_buf, sizeof(sig_buf), "%s %s(%s)",
                         sig->ret_type, sig->name, sig->param_types);
                free(func->signature);
                func->signature = strdup(sig_buf);
            }

            injected++;
        }

        free(matches);
        func = func->next;
    }

    return injected;
}

/*
 * ============================================================================
 * Symbol Export
 * ============================================================================
 */

int e9_fsig_gen_symbols(E9FuncSigDB *db, E9Binary *bin,
                         const char *output_path, const char *format)
{
    (void)db;  /* Not used directly - symbols are in binary */

    if (!bin || !output_path) return -1;

    FILE *fp = fopen(output_path, "w");
    if (!fp) return -1;

    if (!format || strcmp(format, "objcopy") == 0) {
        /* objcopy --add-symbol format */
        E9Symbol *sym = bin->symbols;
        while (sym) {
            if (sym->type == E9_SYM_FUNCTION) {
                fprintf(fp, "--add-symbol %s=.text:0x%lx,function,global\n",
                        sym->name, (unsigned long)(sym->address - bin->base_address));
            }
            sym = sym->next;
        }
    }
    else if (strcmp(format, "ghidra") == 0) {
        /* Ghidra script format */
        fprintf(fp, "# Ghidra symbol injection script\n");
        fprintf(fp, "# Import with: analyzeHeadless ... -postScript ImportSymbols.py\n\n");
        E9Symbol *sym = bin->symbols;
        while (sym) {
            if (sym->type == E9_SYM_FUNCTION) {
                fprintf(fp, "createFunction(toAddr(0x%lx), \"%s\")\n",
                        (unsigned long)sym->address, sym->name);
            }
            sym = sym->next;
        }
    }
    else if (strcmp(format, "ida") == 0) {
        /* IDA Python script format */
        fprintf(fp, "# IDA symbol injection script\n");
        fprintf(fp, "import idc\n\n");
        E9Symbol *sym = bin->symbols;
        while (sym) {
            if (sym->type == E9_SYM_FUNCTION) {
                fprintf(fp, "idc.set_name(0x%lx, \"%s\", idc.SN_CHECK)\n",
                        (unsigned long)sym->address, sym->name);
            }
            sym = sym->next;
        }
    }
    else if (strcmp(format, "json") == 0) {
        /* JSON format for IDE consumption */
        fprintf(fp, "{\n  \"symbols\": [\n");
        E9Symbol *sym = bin->symbols;
        bool first = true;
        while (sym) {
            if (sym->type == E9_SYM_FUNCTION) {
                if (!first) fprintf(fp, ",\n");
                fprintf(fp, "    {\"name\": \"%s\", \"address\": \"0x%lx\", \"type\": \"function\"}",
                        sym->name, (unsigned long)sym->address);
                first = false;
            }
            sym = sym->next;
        }
        fprintf(fp, "\n  ]\n}\n");
    }

    fclose(fp);
    return 0;
}

/*
 * ============================================================================
 * File I/O
 * ============================================================================
 */

int e9_fsigdb_load(E9FuncSigDB *db, const char *path)
{
    /* TODO: Implement JSON loading */
    (void)db;
    (void)path;
    return -1;
}

int e9_fsigdb_save(E9FuncSigDB *db, const char *path)
{
    /* TODO: Implement JSON saving */
    (void)db;
    (void)path;
    return -1;
}
