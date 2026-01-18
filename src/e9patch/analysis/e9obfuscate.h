/*
 * e9obfuscate.h
 * Obfuscation Detection and De-obfuscation Engine
 *
 * Provides:
 * - Binary obfuscation pattern detection
 * - Source code obfuscation detection
 * - De-obfuscation techniques
 * - Obfuscation application (for protecting patches)
 *
 * Detected patterns:
 * - Control flow flattening
 * - Opaque predicates
 * - Dead code insertion
 * - Instruction substitution
 * - VM-based obfuscation
 * - Anti-disassembly tricks
 * - String encryption
 * - Import obfuscation
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

#ifndef E9OBFUSCATE_H
#define E9OBFUSCATE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "e9analysis.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Binary obfuscation techniques
 */
typedef enum {
    E9_OBF_NONE = 0,

    /* Control Flow */
    E9_OBF_CFF,             /* Control Flow Flattening */
    E9_OBF_BOGUS_CF,        /* Bogus control flow (fake branches) */
    E9_OBF_OPAQUE_PRED,     /* Opaque predicates */
    E9_OBF_INDIRECT_BRANCH, /* Indirect branches via table */
    E9_OBF_CALL_OBFUSCATE,  /* call/ret substitution */
    E9_OBF_EXCEPTION_CF,    /* Control flow via exceptions */

    /* Code Mutation */
    E9_OBF_INSN_SUBST,      /* Instruction substitution */
    E9_OBF_DEAD_CODE,       /* Dead code insertion */
    E9_OBF_CODE_TRANSPOSE,  /* Code block reordering */
    E9_OBF_JUNK_BYTES,      /* Junk bytes between instructions */
    E9_OBF_METAMORPHIC,     /* Self-modifying metamorphic code */

    /* Anti-Analysis */
    E9_OBF_ANTI_DISASM,     /* Anti-disassembly tricks */
    E9_OBF_OVERLAPPING,     /* Overlapping instructions */
    E9_OBF_SELF_MODIFY,     /* Self-modifying code */
    E9_OBF_TIMING_CHECK,    /* Timing-based detection */

    /* Data Obfuscation */
    E9_OBF_STRING_ENC,      /* Encrypted strings */
    E9_OBF_CONST_UNFOLD,    /* Constant unfolding */
    E9_OBF_ARRAY_SPLIT,     /* Array/structure splitting */

    /* Import/API */
    E9_OBF_IMPORT_HASH,     /* Import by hash */
    E9_OBF_API_REDIRECT,    /* API call redirection */
    E9_OBF_DYNAMIC_IMPORT,  /* Runtime GetProcAddress */

    /* Virtualization */
    E9_OBF_VM_PROTECT,      /* VM-based protection */
    E9_OBF_BYTECODE,        /* Custom bytecode */

} E9ObfuscationType;

/*
 * Source code obfuscation techniques
 */
typedef enum {
    E9_SRC_OBF_NONE = 0,

    /* Identifiers */
    E9_SRC_OBF_IDENT_MANGLE,    /* Identifier mangling */
    E9_SRC_OBF_IDENT_UNICODE,   /* Unicode lookalikes */

    /* Control Flow */
    E9_SRC_OBF_GOTO_SPAGHETTI,  /* Goto-based spaghetti code */
    E9_SRC_OBF_LOOP_TRANSFORM,  /* Loop transformations */
    E9_SRC_OBF_RECURSION,       /* Recursion insertion */

    /* Data */
    E9_SRC_OBF_STRING_SPLIT,    /* String splitting */
    E9_SRC_OBF_STRING_ENCODE,   /* String encoding */
    E9_SRC_OBF_ARRAY_SHUFFLE,   /* Array index shuffling */
    E9_SRC_OBF_LITERAL_EXPAND,  /* Literal expansion */

    /* Structure */
    E9_SRC_OBF_FUNC_INLINE,     /* Aggressive inlining */
    E9_SRC_OBF_FUNC_OUTLINE,    /* Function outlining/splitting */
    E9_SRC_OBF_FUNC_MERGE,      /* Function merging */
    E9_SRC_OBF_CLASS_FLATTEN,   /* Class hierarchy flattening */

    /* Misc */
    E9_SRC_OBF_MACRO_EXPAND,    /* Macro abuse */
    E9_SRC_OBF_TEMPLATE_ABUSE,  /* Template metaprogramming */
    E9_SRC_OBF_PREPROCESSOR,    /* Preprocessor obfuscation */

} E9SourceObfType;

/*
 * Anti-disassembly trick types
 */
typedef enum {
    E9_ANTIDIS_NONE = 0,

    /* Jump tricks */
    E9_ANTIDIS_JMP_MIDDLE,      /* Jump to middle of instruction */
    E9_ANTIDIS_JMP_SAME,        /* jz/jnz to same target */
    E9_ANTIDIS_CALL_POP,        /* call $+5; pop reg */
    E9_ANTIDIS_PUSH_RET,        /* push addr; ret */

    /* Encoding tricks */
    E9_ANTIDIS_PREFIXES,        /* Redundant prefixes */
    E9_ANTIDIS_LOCK_PREFIX,     /* LOCK on non-memory ops */

    /* Fake instructions */
    E9_ANTIDIS_FAKE_JUMP,       /* Never-taken conditional jump */
    E9_ANTIDIS_DEAD_BRANCH,     /* Dead branch with garbage */

    /* Data as code */
    E9_ANTIDIS_DATA_IN_CODE,    /* Data disguised as instructions */

} E9AntiDisasmType;

/*
 * Detected obfuscation instance
 */
typedef struct E9ObfuscationHit {
    E9ObfuscationType type;
    uint64_t address;
    uint64_t size;
    float confidence;
    char description[256];

    /* Type-specific details */
    union {
        struct {
            uint64_t dispatcher;    /* CFF dispatcher address */
            uint32_t num_blocks;    /* Number of flattened blocks */
            uint64_t *block_addrs;  /* Block addresses */
        } cff;

        struct {
            uint64_t predicate_addr;
            uint64_t true_target;
            uint64_t false_target;
            bool always_true;
        } opaque_pred;

        struct {
            E9AntiDisasmType trick;
            uint64_t real_target;   /* Actual destination */
        } anti_disasm;

        struct {
            uint64_t string_addr;
            size_t string_len;
            char *decrypted;        /* Decrypted string if known */
        } string_enc;

        struct {
            uint32_t hash_value;
            char *resolved_name;    /* Resolved API name if found */
        } import_hash;

        struct {
            uint64_t vm_entry;
            uint64_t vm_handlers;
            uint32_t num_handlers;
            char vm_name[32];       /* e.g., "VMProtect", "Themida" */
        } vm;
    } detail;

    struct E9ObfuscationHit *next;
} E9ObfuscationHit;

/*
 * Obfuscation analysis result
 */
typedef struct {
    E9ObfuscationHit *hits;
    uint32_t num_hits;

    /* Summary */
    uint32_t obfuscation_score;     /* 0-100 overall obfuscation level */
    bool has_cff;
    bool has_opaque_pred;
    bool has_anti_disasm;
    bool has_string_enc;
    bool has_vm;

    /* Function-level metrics */
    struct {
        E9Function *func;
        uint32_t complexity_increase;   /* vs. non-obfuscated */
        uint32_t dead_code_percent;
        uint32_t indirect_calls;
        bool is_flattened;
    } *func_metrics;
    uint32_t num_funcs;

} E9ObfuscationAnalysis;

/*
 * ============================================================================
 * Detection API
 * ============================================================================
 */

/*
 * Full obfuscation analysis
 */
E9ObfuscationAnalysis *e9_obfuscation_analyze(E9Binary *bin);

/*
 * Free analysis
 */
void e9_obfuscation_free(E9ObfuscationAnalysis *analysis);

/*
 * Detect specific technique at address
 */
E9ObfuscationHit *e9_obfuscation_detect_at(E9Binary *bin, uint64_t addr,
                                            E9ObfuscationType type);

/*
 * Get technique name
 */
const char *e9_obfuscation_name(E9ObfuscationType type);

/*
 * ============================================================================
 * Control Flow Flattening (CFF) Detection
 * ============================================================================
 */

/*
 * Detect if function uses CFF
 */
bool e9_cff_detect(E9Binary *bin, E9Function *func);

/*
 * Find CFF dispatcher
 */
uint64_t e9_cff_find_dispatcher(E9Binary *bin, E9Function *func);

/*
 * Recover original CFG from CFF
 */
E9CFG *e9_cff_recover_cfg(E9Binary *bin, E9Function *func);

/*
 * ============================================================================
 * Opaque Predicate Detection
 * ============================================================================
 */

/*
 * Detect opaque predicate at conditional branch
 */
bool e9_opaque_detect(E9Binary *bin, uint64_t addr, bool *always_true);

/*
 * Find all opaque predicates in function
 */
E9ObfuscationHit *e9_opaque_scan(E9Binary *bin, E9Function *func);

/*
 * Remove opaque predicates (simplify CFG)
 */
int e9_opaque_remove(E9Binary *bin, E9Function *func);

/*
 * ============================================================================
 * Anti-Disassembly Detection
 * ============================================================================
 */

/*
 * Detect anti-disassembly at address
 */
E9AntiDisasmType e9_antidisasm_detect(E9Binary *bin, uint64_t addr);

/*
 * Scan for anti-disassembly tricks
 */
E9ObfuscationHit *e9_antidisasm_scan(E9Binary *bin);

/*
 * Get correct disassembly (handling tricks)
 */
E9Instruction *e9_antidisasm_disasm(E9Binary *bin, uint64_t addr);

/*
 * ============================================================================
 * String Encryption Detection
 * ============================================================================
 */

typedef struct {
    uint64_t address;
    size_t length;
    uint8_t *encrypted;
    char *decrypted;            /* NULL if not decrypted */
    uint64_t decrypt_func;      /* Address of decryption function */
    E9CryptAlgo algorithm;
} E9EncryptedString;

/*
 * Find encrypted strings
 */
E9EncryptedString *e9_string_enc_scan(E9Binary *bin, uint32_t *count);

/*
 * Try to decrypt string
 */
char *e9_string_decrypt(E9Binary *bin, E9EncryptedString *str);

/*
 * Emulate string decryption function
 */
char *e9_string_decrypt_emulate(E9Binary *bin, uint64_t func_addr,
                                 const uint8_t *encrypted, size_t len);

/*
 * ============================================================================
 * Import Obfuscation
 * ============================================================================
 */

typedef struct {
    uint32_t hash;
    char *name;                 /* Resolved name or NULL */
    uint64_t call_site;
} E9HashImport;

/*
 * Known hash algorithms for import resolution
 */
typedef enum {
    E9_HASH_UNKNOWN,
    E9_HASH_ROR13,              /* Common Win32 hash */
    E9_HASH_CRC32,
    E9_HASH_DJBX33A,
    E9_HASH_SDBM,
    E9_HASH_FNV1A,
    E9_HASH_MURMUR,
    E9_HASH_CUSTOM,
} E9HashAlgo;

/*
 * Detect import hashing
 */
E9HashImport *e9_import_hash_scan(E9Binary *bin, uint32_t *count);

/*
 * Resolve hash to API name
 */
const char *e9_import_hash_resolve(uint32_t hash, E9HashAlgo algo);

/*
 * Detect hash algorithm used
 */
E9HashAlgo e9_import_hash_algo_detect(E9Binary *bin);

/*
 * ============================================================================
 * VM/Bytecode Obfuscation
 * ============================================================================
 */

typedef struct {
    char name[32];              /* VM protector name */
    uint64_t entry;             /* VM entry point */
    uint64_t handler_table;     /* Handler dispatch table */
    uint32_t num_handlers;
    uint32_t bytecode_size;

    /* Handler analysis */
    struct {
        uint8_t opcode;
        uint64_t handler_addr;
        char semantics[64];     /* Inferred operation */
    } *handlers;

} E9VMInfo;

/*
 * Detect VM protection
 */
E9VMInfo *e9_vm_detect(E9Binary *bin);

/*
 * Analyze VM handlers
 */
int e9_vm_analyze_handlers(E9Binary *bin, E9VMInfo *vm);

/*
 * Attempt to devirtualize (lift bytecode back to native)
 */
uint8_t *e9_vm_devirtualize(E9Binary *bin, E9VMInfo *vm,
                             uint64_t func_addr, size_t *out_size);

/*
 * ============================================================================
 * De-obfuscation
 * ============================================================================
 */

/*
 * De-obfuscation options
 */
typedef struct {
    bool remove_dead_code;
    bool simplify_cff;
    bool remove_opaque_pred;
    bool decrypt_strings;
    bool resolve_imports;
    bool fix_anti_disasm;
    bool devirtualize;
} E9DeobfOptions;

/*
 * Apply de-obfuscation transforms
 */
uint8_t *e9_deobfuscate(E9Binary *bin, E9DeobfOptions *opts, size_t *out_size);

/*
 * De-obfuscate specific function
 */
uint8_t *e9_deobfuscate_func(E9Binary *bin, E9Function *func,
                              E9DeobfOptions *opts, size_t *out_size);

/*
 * ============================================================================
 * Obfuscation Application (for protecting patches)
 * ============================================================================
 */

typedef struct {
    /* Control Flow */
    bool apply_cff;
    int cff_blocks;             /* Number of flattened blocks */

    bool insert_opaque_pred;
    int opaque_density;         /* How many per function */

    bool add_bogus_cf;
    int bogus_cf_ratio;

    /* Code */
    bool insert_dead_code;
    int dead_code_percent;

    bool substitute_insns;
    bool add_junk_bytes;

    /* Data */
    bool encrypt_strings;
    E9CryptAlgo string_crypto;

    bool obfuscate_constants;

    /* Anti-Analysis */
    bool add_anti_disasm;
    bool add_timing_checks;

} E9ObfuscateOptions;

/*
 * Apply obfuscation to code
 */
uint8_t *e9_obfuscate(const uint8_t *code, size_t size,
                      E9Arch arch, E9ObfuscateOptions *opts,
                      size_t *out_size);

/*
 * Generate opaque predicate code
 */
uint8_t *e9_gen_opaque_predicate(E9Arch arch, bool always_true, size_t *out_size);

/*
 * Generate dead code
 */
uint8_t *e9_gen_dead_code(E9Arch arch, size_t desired_size, size_t *out_size);

/*
 * Substitute instruction with equivalent sequence
 */
uint8_t *e9_insn_substitute(E9Instruction *insn, E9Arch arch, size_t *out_size);

/*
 * ============================================================================
 * Source Code Obfuscation Detection
 * ============================================================================
 */

typedef struct {
    E9SourceObfType type;
    uint32_t line;
    uint32_t column;
    float confidence;
    char description[256];
} E9SourceObfHit;

/*
 * Analyze source code for obfuscation
 */
E9SourceObfHit *e9_source_obf_analyze(const char *source, size_t len,
                                       const char *language, uint32_t *count);

/*
 * Detect identifier mangling
 */
bool e9_source_detect_mangling(const char *source, size_t len);

/*
 * Calculate source code complexity metrics
 */
typedef struct {
    uint32_t cyclomatic;        /* Cyclomatic complexity */
    uint32_t cognitive;         /* Cognitive complexity */
    uint32_t halstead_volume;
    float maintainability;      /* Maintainability index */
    uint32_t max_nesting;
    uint32_t goto_count;
    float avg_identifier_len;
    uint32_t unique_identifiers;
} E9SourceMetrics;

E9SourceMetrics e9_source_metrics(const char *source, size_t len, const char *lang);

#ifdef __cplusplus
}
#endif

#endif /* E9OBFUSCATE_H */
