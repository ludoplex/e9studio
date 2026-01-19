/*
 * e9builtin.h
 * Self-Contained Analysis Engine (Zero Dependencies)
 *
 * This provides ALL analysis capabilities built into e9studio.com
 * without requiring any external tools. External tools (binwalk, etc.)
 * are optional enhancements only.
 *
 * Architecture:
 *   e9studio.com (standalone APE)
 *       │
 *       ├── Built-in analysis (this file)
 *       │   ├── Signature database
 *       │   ├── Multi-arch disassembly
 *       │   ├── Compression/decompression
 *       │   ├── Polyglot detection
 *       │   └── Format parsing
 *       │
 *       ├── WebSocket/IPC server
 *       │   └── IDE plugins connect here
 *       │
 *       └── Optional: external tool enhancement
 *           └── e9extern.h (if binwalk/polyfile available)
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

#ifndef E9BUILTIN_H
#define E9BUILTIN_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * SIGNATURE DATABASE (built-in, no binwalk needed)
 * ============================================================================
 */

typedef struct {
    const char *name;           /* Format name */
    const char *description;
    const uint8_t *magic;       /* Magic bytes */
    uint8_t magic_len;
    int16_t offset;             /* Offset from start (-1 = scan) */
    uint8_t format_id;          /* E9FormatType */
} E9Signature;

/* Get built-in signature database */
const E9Signature *e9_builtin_signatures(size_t *count);

/* Scan data for all signatures */
typedef struct {
    uint64_t offset;
    uint8_t format_id;
    const char *name;
    const char *description;
} E9SignatureHit;

E9SignatureHit *e9_builtin_scan(const uint8_t *data, size_t size, size_t *count);
void e9_builtin_scan_free(E9SignatureHit *hits);

/*
 * ============================================================================
 * MULTI-ARCH DISASSEMBLY (built-in, no capstone needed)
 * ============================================================================
 */

/* Supported architectures */
#define E9_ARCH_X86_64   1
#define E9_ARCH_AARCH64  2
#define E9_ARCH_RISCV64  3

typedef struct {
    uint64_t address;
    uint8_t size;
    uint8_t bytes[15];
    char mnemonic[12];
    char operands[64];
    uint8_t category;           /* E9_INSN_* */
    uint64_t branch_target;     /* If branch/call */
    bool is_branch;
    bool is_call;
    bool is_ret;
} E9DisasmInsn;

/* Disassemble one instruction */
int e9_builtin_disasm_one(const uint8_t *code, size_t max_len,
                          uint64_t addr, int arch, E9DisasmInsn *out);

/* Disassemble multiple instructions */
E9DisasmInsn *e9_builtin_disasm(const uint8_t *code, size_t size,
                                 uint64_t addr, int arch, size_t max_insns,
                                 size_t *out_count);
void e9_builtin_disasm_free(E9DisasmInsn *insns);

/* Format instruction as string */
int e9_builtin_disasm_fmt(E9DisasmInsn *insn, char *buf, size_t buf_size);

/*
 * ============================================================================
 * COMPRESSION (built-in implementations, no zlib needed)
 * ============================================================================
 */

/* Detect compression type */
typedef enum {
    E9_COMP_NONE = 0,
    E9_COMP_DEFLATE,    /* zlib/gzip */
    E9_COMP_LZ4,
    E9_COMP_ZSTD,
    E9_COMP_LZMA,
    E9_COMP_RLE,        /* Simple RLE */
    E9_COMP_STORE,      /* Stored (no compression) */
} E9CompType;

E9CompType e9_builtin_comp_detect(const uint8_t *data, size_t size);

/* Built-in deflate (minimal implementation) */
uint8_t *e9_builtin_inflate(const uint8_t *data, size_t size, size_t *out_size);
uint8_t *e9_builtin_deflate(const uint8_t *data, size_t size,
                            int level, size_t *out_size);

/* Built-in LZ4 (simple implementation) */
uint8_t *e9_builtin_lz4_decompress(const uint8_t *data, size_t size,
                                    size_t max_out, size_t *out_size);

/* Built-in RLE */
uint8_t *e9_builtin_rle_decompress(const uint8_t *data, size_t size,
                                    size_t *out_size);

/*
 * ============================================================================
 * FORMAT PARSERS (built-in, no LIEF needed)
 * ============================================================================
 */

/* ELF parsing */
typedef struct {
    uint8_t elf_class;          /* 1=32bit, 2=64bit */
    uint8_t endian;             /* 1=LE, 2=BE */
    uint16_t machine;
    uint64_t entry;
    uint64_t phoff, shoff;
    uint16_t phnum, shnum;
    uint16_t shstrndx;
} E9ElfHeader;

typedef struct {
    char name[64];
    uint32_t type;
    uint64_t flags;
    uint64_t addr;
    uint64_t offset;
    uint64_t size;
} E9ElfSection;

typedef struct {
    char name[256];
    uint64_t value;
    uint64_t size;
    uint8_t type;
    uint8_t bind;
} E9ElfSymbol;

int e9_builtin_elf_parse(const uint8_t *data, size_t size, E9ElfHeader *hdr);
E9ElfSection *e9_builtin_elf_sections(const uint8_t *data, size_t size,
                                       E9ElfHeader *hdr, size_t *count);
E9ElfSymbol *e9_builtin_elf_symbols(const uint8_t *data, size_t size,
                                     E9ElfHeader *hdr, size_t *count);

/* PE parsing */
typedef struct {
    uint16_t machine;
    uint16_t num_sections;
    uint32_t timestamp;
    uint64_t image_base;
    uint32_t entry_rva;
    uint32_t section_align;
    uint32_t file_align;
} E9PeHeader;

typedef struct {
    char name[9];
    uint32_t virtual_size;
    uint32_t virtual_addr;
    uint32_t raw_size;
    uint32_t raw_ptr;
    uint32_t characteristics;
} E9PeSection;

int e9_builtin_pe_parse(const uint8_t *data, size_t size, E9PeHeader *hdr);
E9PeSection *e9_builtin_pe_sections(const uint8_t *data, size_t size,
                                     E9PeHeader *hdr, size_t *count);

/* ZIP parsing (for ZipOS) */
typedef struct {
    char name[256];
    uint64_t offset;            /* Local header offset */
    uint64_t comp_size;
    uint64_t uncomp_size;
    uint16_t method;            /* 0=store, 8=deflate */
    uint32_t crc32;
} E9ZipEntry;

typedef struct {
    E9ZipEntry *entries;
    size_t num_entries;
    uint64_t central_dir_offset;
    uint64_t central_dir_size;
} E9ZipArchive;

E9ZipArchive *e9_builtin_zip_open(const uint8_t *data, size_t size);
void e9_builtin_zip_close(E9ZipArchive *zip);
uint8_t *e9_builtin_zip_extract(E9ZipArchive *zip, const char *name,
                                 size_t *out_size);

/*
 * ============================================================================
 * ENTROPY & CRYPTO DETECTION (built-in)
 * ============================================================================
 */

typedef struct {
    double entropy;             /* Shannon entropy 0-8 */
    double chi_square;
    bool likely_encrypted;
    bool likely_compressed;
    bool likely_random;
    bool likely_text;
} E9EntropyInfo;

E9EntropyInfo e9_builtin_entropy(const uint8_t *data, size_t size);

/* Entropy map (per block) */
double *e9_builtin_entropy_map(const uint8_t *data, size_t size,
                                size_t block_size, size_t *num_blocks);

/* XOR key detection */
typedef struct {
    uint8_t key[256];
    size_t key_len;
    float confidence;
    bool is_single_byte;
} E9XorKey;

E9XorKey e9_builtin_xor_detect(const uint8_t *data, size_t size);
uint8_t *e9_builtin_xor_decrypt(const uint8_t *data, size_t size,
                                 const uint8_t *key, size_t key_len);

/*
 * ============================================================================
 * STRING EXTRACTION (built-in)
 * ============================================================================
 */

typedef struct {
    uint64_t offset;
    char *value;
    size_t length;
    bool is_wide;               /* UTF-16 */
    bool is_encrypted;          /* Looks encrypted */
} E9String;

E9String *e9_builtin_strings(const uint8_t *data, size_t size,
                              size_t min_len, size_t *count);
void e9_builtin_strings_free(E9String *strings, size_t count);

/*
 * ============================================================================
 * POLYGLOT DETECTION (built-in)
 * ============================================================================
 */

typedef struct {
    bool is_polyglot;
    bool is_ape;

    /* Which formats are valid */
    bool has_elf;
    bool has_pe;
    bool has_macho;
    bool has_zip;
    bool has_shell;

    /* APE-specific offsets */
    uint64_t elf_offset;
    uint64_t pe_offset;
    uint64_t macho_offset;
    uint64_t zip_offset;
    uint64_t shell_offset;
} E9PolyglotInfo;

E9PolyglotInfo e9_builtin_polyglot(const uint8_t *data, size_t size);

/*
 * ============================================================================
 * PACKER DETECTION (built-in)
 * ============================================================================
 */

typedef struct {
    const char *name;           /* Packer name */
    const char *version;
    float confidence;
    uint64_t oep_hint;          /* Original entry point hint */
    bool is_packed;
} E9PackerInfo;

E9PackerInfo e9_builtin_packer_detect(const uint8_t *data, size_t size);

/* UPX unpacking (built-in) */
uint8_t *e9_builtin_upx_unpack(const uint8_t *data, size_t size,
                                size_t *out_size);

/*
 * ============================================================================
 * IDE COMMUNICATION PROTOCOL
 * ============================================================================
 */

/* Message types for IDE plugins */
typedef enum {
    E9_MSG_HELLO = 1,           /* Handshake */
    E9_MSG_LOAD_BINARY,         /* Load binary for analysis */
    E9_MSG_ANALYZE,             /* Run analysis */
    E9_MSG_DISASM,              /* Get disassembly */
    E9_MSG_DECOMPILE,           /* Get decompilation */
    E9_MSG_SYMBOLS,             /* Get symbols */
    E9_MSG_GOTO,                /* Navigate to address */
    E9_MSG_PATCH,               /* Apply patch */
    E9_MSG_BREAKPOINT,          /* Set/clear breakpoint */
    E9_MSG_SOURCE_CHANGE,       /* Source file changed */
    E9_MSG_COMPILE,             /* Compile source */
    E9_MSG_APPLY_DIFF,          /* Apply compiled diff */
    E9_MSG_SAVE,                /* Save binary */
    E9_MSG_STATUS,              /* Status update */
    E9_MSG_ERROR,               /* Error message */
} E9MsgType;

/* Message header (JSON-RPC style) */
typedef struct {
    uint32_t magic;             /* 'E9ST' */
    uint32_t length;            /* Payload length */
    uint16_t type;              /* E9MsgType */
    uint16_t id;                /* Request ID */
} E9MsgHeader;

/* WebSocket server for IDE communication */
int e9_server_start(int port);
void e9_server_stop(void);
int e9_server_broadcast(E9MsgType type, const char *json);

/*
 * ============================================================================
 * UNIFIED ANALYSIS API
 * ============================================================================
 */

/* Full analysis result (everything built-in) */
typedef struct {
    /* Basic info */
    size_t size;
    uint8_t sha256[32];

    /* Format detection */
    E9PolyglotInfo polyglot;
    E9PackerInfo packer;
    E9EntropyInfo entropy;

    /* Parsed structure (based on format) */
    union {
        struct {
            E9ElfHeader header;
            E9ElfSection *sections;
            size_t num_sections;
            E9ElfSymbol *symbols;
            size_t num_symbols;
        } elf;
        struct {
            E9PeHeader header;
            E9PeSection *sections;
            size_t num_sections;
        } pe;
        struct {
            E9ZipArchive *archive;
        } zip;
    } parsed;

    /* Signatures found */
    E9SignatureHit *signatures;
    size_t num_signatures;

    /* Strings */
    E9String *strings;
    size_t num_strings;

} E9AnalysisResult;

/* Run complete analysis (all built-in, no external deps) */
E9AnalysisResult *e9_builtin_analyze(const uint8_t *data, size_t size);
void e9_builtin_analyze_free(E9AnalysisResult *result);

#ifdef __cplusplus
}
#endif

#endif /* E9BUILTIN_H */
