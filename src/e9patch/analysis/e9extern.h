/*
 * e9extern.h
 * External Tool Integration Layer
 *
 * Wraps external analysis tools rather than reimplementing:
 * - binwalk: Signature scanning, extraction
 * - polyfile: Polyglot detection
 * - polytracker: Taint tracking (via instrumentation)
 * - capstone: Multi-arch disassembly
 * - keystone: Multi-arch assembly
 * - LIEF: Binary parsing
 * - zlib/lzma/zstd: Compression
 *
 * Falls back to built-in minimal implementations when tools unavailable.
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

#ifndef E9EXTERN_H
#define E9EXTERN_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Tool availability flags (detected at runtime)
 */
typedef struct {
    bool has_binwalk;
    bool has_polyfile;
    bool has_polytracker;
    bool has_capstone;
    bool has_keystone;
    bool has_lief;
    bool has_zlib;
    bool has_lzma;
    bool has_zstd;
    bool has_objdump;
    bool has_readelf;
    bool has_nm;
    bool has_strings;
    bool has_file;

    /* Tool paths (if found) */
    char binwalk_path[256];
    char polyfile_path[256];
    char polytracker_path[256];
    char objdump_path[256];
    char readelf_path[256];
} E9ExternTools;

/*
 * Detect available tools
 */
E9ExternTools *e9_extern_detect(void);

/*
 * Get cached tool info
 */
const E9ExternTools *e9_extern_tools(void);

/*
 * ============================================================================
 * binwalk Integration
 * ============================================================================
 */

typedef struct {
    uint64_t offset;
    char description[256];
    char type[64];
    size_t size;            /* If extractable */
} E9BinwalkResult;

/*
 * Run binwalk signature scan
 * Returns NULL if binwalk not available (use builtin fallback)
 */
E9BinwalkResult *e9_binwalk_scan(const char *filepath, uint32_t *count);
E9BinwalkResult *e9_binwalk_scan_mem(const uint8_t *data, size_t size, uint32_t *count);

/*
 * Run binwalk extraction
 */
int e9_binwalk_extract(const char *filepath, const char *outdir);

/*
 * Run binwalk entropy analysis
 */
typedef struct {
    double *entropy;        /* Entropy values */
    size_t num_blocks;
    size_t block_size;
} E9BinwalkEntropy;

E9BinwalkEntropy *e9_binwalk_entropy(const char *filepath);
void e9_binwalk_entropy_free(E9BinwalkEntropy *ent);

/*
 * ============================================================================
 * polyfile Integration
 * ============================================================================
 */

typedef struct {
    char format[64];
    uint64_t offset;
    uint64_t size;
    float confidence;
    char mime_type[128];

    /* Nested formats */
    struct E9PolyfileMatch *children;
    uint32_t num_children;
} E9PolyfileMatch;

/*
 * Run polyfile analysis
 */
E9PolyfileMatch *e9_polyfile_scan(const char *filepath, uint32_t *count);

/*
 * Get polyfile JSON output (full detail)
 */
char *e9_polyfile_json(const char *filepath);

/*
 * Check if file is polyglot
 */
bool e9_polyfile_is_polyglot(const char *filepath);

/*
 * ============================================================================
 * Capstone Disassembly (if available, else use builtin)
 * ============================================================================
 */

/* Architecture constants (mirror capstone) */
#define E9_CS_ARCH_X86      3
#define E9_CS_ARCH_ARM64    5

/* Mode constants */
#define E9_CS_MODE_64       (1 << 3)

typedef struct {
    uint64_t address;
    uint16_t size;
    uint8_t bytes[24];
    char mnemonic[32];
    char op_str[160];

    /* Detailed info (if capstone available) */
    uint8_t *detail;        /* Opaque capstone detail */
} E9CapstoneInsn;

/*
 * Initialize disassembler for architecture
 */
void *e9_capstone_open(int arch, int mode);
void e9_capstone_close(void *handle);

/*
 * Disassemble instructions
 */
size_t e9_capstone_disasm(void *handle, const uint8_t *code, size_t size,
                          uint64_t addr, size_t count, E9CapstoneInsn **insns);

void e9_capstone_free(E9CapstoneInsn *insns, size_t count);

/*
 * ============================================================================
 * Keystone Assembly (if available)
 * ============================================================================
 */

/*
 * Assemble instruction string
 */
uint8_t *e9_keystone_asm(int arch, int mode, const char *assembly,
                          uint64_t addr, size_t *out_size, size_t *out_count);

void e9_keystone_free(uint8_t *code);

/*
 * ============================================================================
 * LIEF Binary Parsing (if available)
 * ============================================================================
 */

typedef struct {
    char name[256];
    uint64_t address;
    uint64_t size;
    int type;               /* Function, data, etc. */
    bool is_exported;
    bool is_imported;
} E9LiefSymbol;

typedef struct {
    char name[64];
    uint64_t virtual_address;
    uint64_t virtual_size;
    uint64_t file_offset;
    uint64_t file_size;
    uint32_t characteristics;
} E9LiefSection;

/*
 * Parse binary with LIEF
 */
E9LiefSymbol *e9_lief_symbols(const char *filepath, uint32_t *count);
E9LiefSection *e9_lief_sections(const char *filepath, uint32_t *count);

/*
 * Get imports/exports
 */
char **e9_lief_imports(const char *filepath, uint32_t *count);
char **e9_lief_exports(const char *filepath, uint32_t *count);

/*
 * Modify binary (add section, patch, etc.)
 */
int e9_lief_add_section(const char *filepath, const char *name,
                        const uint8_t *data, size_t size, const char *outpath);

/*
 * ============================================================================
 * Compression Libraries
 * ============================================================================
 */

/* zlib */
uint8_t *e9_zlib_compress(const uint8_t *data, size_t size,
                          int level, size_t *out_size);
uint8_t *e9_zlib_decompress(const uint8_t *data, size_t size,
                            size_t max_out, size_t *out_size);

/* LZMA */
uint8_t *e9_lzma_compress(const uint8_t *data, size_t size,
                          int level, size_t *out_size);
uint8_t *e9_lzma_decompress(const uint8_t *data, size_t size,
                            size_t *out_size);

/* Zstandard */
uint8_t *e9_zstd_compress(const uint8_t *data, size_t size,
                          int level, size_t *out_size);
uint8_t *e9_zstd_decompress(const uint8_t *data, size_t size,
                            size_t *out_size);

/*
 * ============================================================================
 * System Tool Wrappers
 * ============================================================================
 */

/*
 * Run 'file' command
 */
char *e9_file_type(const char *filepath);

/*
 * Run 'strings' command
 */
char **e9_strings_extract(const char *filepath, size_t min_len, uint32_t *count);

/*
 * Run 'objdump' disassembly
 */
char *e9_objdump_disasm(const char *filepath, uint64_t start, uint64_t end);

/*
 * Run 'readelf' for ELF info
 */
char *e9_readelf_headers(const char *filepath);
char *e9_readelf_symbols(const char *filepath);
char *e9_readelf_sections(const char *filepath);

/*
 * Run 'nm' for symbols
 */
E9LiefSymbol *e9_nm_symbols(const char *filepath, uint32_t *count);

/*
 * ============================================================================
 * Utility Functions
 * ============================================================================
 */

/*
 * Run external command, capture output
 */
char *e9_extern_run(const char *cmd, int *exit_code);

/*
 * Run command with input data (via temp file or stdin)
 */
char *e9_extern_run_input(const char *cmd, const uint8_t *input,
                          size_t input_size, int *exit_code);

/*
 * Check if command exists in PATH
 */
bool e9_extern_exists(const char *cmd);

/*
 * Get path to command
 */
char *e9_extern_which(const char *cmd);

/*
 * Write temp file, return path
 */
char *e9_extern_tempfile(const uint8_t *data, size_t size, const char *suffix);

/*
 * Clean up temp file
 */
void e9_extern_tempfile_free(char *path);

#ifdef __cplusplus
}
#endif

#endif /* E9EXTERN_H */
