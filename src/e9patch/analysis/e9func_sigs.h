/*
 * e9func_sigs.h
 * Function Signature Matching for Symbol Injection
 *
 * Provides automatic function identification in stripped binaries using:
 * - Prologue/epilogue pattern matching
 * - Known library function signatures
 * - Cosmopolitan libc function recognition
 * - Compiler-specific pattern detection
 *
 * This enables symbol injection without debug info, critical for
 * binary rewriting of stripped production binaries.
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

#ifndef E9FUNC_SIGS_H
#define E9FUNC_SIGS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Function signature types
 */
typedef enum {
    E9_FSIG_PROLOGUE,       /* Function prologue pattern */
    E9_FSIG_EPILOGUE,       /* Function epilogue pattern */
    E9_FSIG_BODY,           /* Specific instruction sequence in body */
    E9_FSIG_CONSTANT,       /* Magic constants used in function */
    E9_FSIG_SYSCALL,        /* Syscall number identification */
    E9_FSIG_STRING_REF,     /* Reference to known string */
} E9FuncSigType;

/*
 * Architecture for signatures
 */
typedef enum {
    E9_FSIG_ARCH_ANY = 0,
    E9_FSIG_ARCH_X64,
    E9_FSIG_ARCH_AARCH64,
} E9FuncSigArch;

/*
 * Confidence levels for matches
 */
typedef enum {
    E9_CONF_LOW = 1,        /* Pattern match only */
    E9_CONF_MEDIUM = 2,     /* Pattern + context match */
    E9_CONF_HIGH = 3,       /* Multiple confirmations */
    E9_CONF_CERTAIN = 4,    /* Unique signature or debug info */
} E9ConfLevel;

/*
 * Function signature definition
 */
typedef struct E9FuncSig {
    const char *name;           /* Function name */
    const char *lib;            /* Library origin (e.g., "libc", "cosmopolitan") */
    E9FuncSigType type;
    E9FuncSigArch arch;

    /* Pattern data */
    const uint8_t *pattern;     /* Byte pattern */
    const uint8_t *mask;        /* Mask for wildcards (0 = wildcard, 0xFF = exact) */
    size_t pattern_len;
    int32_t offset;             /* Offset from function start (can be negative) */

    /* Additional matching criteria */
    uint32_t min_size;          /* Minimum function size */
    uint32_t max_size;          /* Maximum function size (0 = unlimited) */
    const char *ref_string;     /* String this function references */
    int32_t syscall_nr;         /* Syscall number (-1 = N/A) */

    /* Type signature for decompilation */
    const char *ret_type;       /* Return type string */
    const char *param_types;    /* Parameter types (comma-separated) */
    uint32_t flags;             /* E9_FSIG_FLAG_* */
} E9FuncSig;

/* Signature flags */
#define E9_FSIG_FLAG_NORETURN    0x0001  /* Function never returns */
#define E9_FSIG_FLAG_LEAF        0x0002  /* No calls to other functions */
#define E9_FSIG_FLAG_VARIADIC    0x0004  /* Variable arguments */
#define E9_FSIG_FLAG_WEAK        0x0008  /* May be overridden */

/*
 * Function signature match result
 */
typedef struct E9FuncSigMatch {
    const E9FuncSig *sig;       /* Matched signature */
    uint64_t address;           /* Function address */
    E9ConfLevel confidence;     /* Match confidence */
    uint32_t score;             /* Match score for ranking */
} E9FuncSigMatch;

/*
 * Signature database handle
 */
typedef struct E9FuncSigDB E9FuncSigDB;

/*
 * ============================================================================
 * API
 * ============================================================================
 */

/*
 * Create signature database with built-in signatures
 */
E9FuncSigDB *e9_fsigdb_create(void);

/*
 * Free signature database
 */
void e9_fsigdb_free(E9FuncSigDB *db);

/*
 * Add custom signature
 */
int e9_fsigdb_add(E9FuncSigDB *db, const E9FuncSig *sig);

/*
 * Load signatures from file (JSON format)
 */
int e9_fsigdb_load(E9FuncSigDB *db, const char *path);

/*
 * Save signatures to file
 */
int e9_fsigdb_save(E9FuncSigDB *db, const char *path);

/*
 * Get number of signatures in database
 */
size_t e9_fsigdb_count(const E9FuncSigDB *db);

/*
 * Match function at address against database
 * Returns array of matches sorted by confidence (caller must free)
 */
E9FuncSigMatch *e9_fsig_match(E9FuncSigDB *db, const uint8_t *code,
                               size_t code_size, uint64_t base_addr,
                               uint64_t func_addr, int arch,
                               uint32_t *num_matches);

/*
 * Match all functions in binary
 * Integrates with E9Binary from e9analysis.h
 */
struct E9Binary;  /* Forward declaration */
int e9_fsig_analyze_binary(E9FuncSigDB *db, struct E9Binary *bin);

/*
 * Generate symbol injection script
 * Outputs commands to add symbols (e.g., for objcopy or llvm-objcopy)
 */
int e9_fsig_gen_symbols(E9FuncSigDB *db, struct E9Binary *bin,
                         const char *output_path, const char *format);

/*
 * ============================================================================
 * Built-in Signature Categories
 * ============================================================================
 */

/* Standard C library (glibc, musl, cosmopolitan) */
extern const E9FuncSig E9_SIGS_LIBC[];
extern const size_t E9_SIGS_LIBC_COUNT;

/* Compiler intrinsics and builtins */
extern const E9FuncSig E9_SIGS_COMPILER[];
extern const size_t E9_SIGS_COMPILER_COUNT;

/* C++ runtime (exception handling, RTTI) */
extern const E9FuncSig E9_SIGS_CXXRT[];
extern const size_t E9_SIGS_CXXRT_COUNT;

/* Common crypto functions (OpenSSL, mbedtls patterns) */
extern const E9FuncSig E9_SIGS_CRYPTO[];
extern const size_t E9_SIGS_CRYPTO_COUNT;

/* System call wrappers */
extern const E9FuncSig E9_SIGS_SYSCALL[];
extern const size_t E9_SIGS_SYSCALL_COUNT;

#ifdef __cplusplus
}
#endif

#endif /* E9FUNC_SIGS_H */
