/*
 * e9vendor.h
 * Unified E9Studio Vendor Library
 *
 * Self-contained analysis components for e9studio.com with ZERO external
 * dependencies. All functionality is built directly into the single APE binary.
 *
 * Components:
 * - Signature scanning (binwalk-inspired)
 * - x86-64 disassembly
 * - AArch64 disassembly
 * - Format detection
 * - Binary analysis utilities
 *
 * Sources:
 * - Signatures extracted from binwalk (https://github.com/ReFirmLabs/binwalk)
 * - Disassembly inspired by capstone (https://github.com/capstone-engine/capstone)
 * - Format detection from polyfile (https://github.com/trailofbits/polyfile)
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

#ifndef E9VENDOR_H
#define E9VENDOR_H

/* Include all vendor components */
#include "e9signatures.h"
#include "e9disasm_x86.h"
#include "e9disasm_arm64.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * Unified Analysis API
 * ============================================================================
 */

/*
 * Binary architecture
 */
typedef enum {
    E9_ARCH_UNKNOWN = 0,
    E9_ARCH_X86,
    E9_ARCH_X86_64,
    E9_ARCH_ARM,
    E9_ARCH_ARM64,
    E9_ARCH_MIPS,
    E9_ARCH_RISCV,
    E9_ARCH_WASM,
} E9Arch;

/*
 * Binary format
 */
typedef enum {
    E9_FMT_UNKNOWN = 0,
    E9_FMT_ELF,
    E9_FMT_PE,
    E9_FMT_MACHO,
    E9_FMT_APE,
    E9_FMT_WASM,
    E9_FMT_RAW,
} E9Format;

/*
 * Quick binary identification result
 */
typedef struct {
    E9Format format;
    E9Arch arch;
    bool is_64bit;
    bool is_little_endian;
    bool is_executable;
    bool is_shared_lib;
    bool is_relocatable;
    bool is_polyglot;           /* Multiple valid formats */

    /* Embedded content found */
    uint32_t num_signatures;
    E9SigMatch *signatures;

    /* Entry point */
    uint64_t entry_point;

    /* Sections/segments summary */
    uint32_t num_sections;
    uint32_t num_segments;

    /* Human-readable description */
    char description[256];

} E9BinaryInfo;

/*
 * Quick binary identification
 */
E9BinaryInfo *e9_identify(const uint8_t *data, size_t size);
void e9_identify_free(E9BinaryInfo *info);

/*
 * ============================================================================
 * Multi-Architecture Disassembly
 * ============================================================================
 */

/*
 * Generic instruction representation
 */
typedef struct {
    uint64_t address;
    uint8_t length;
    uint8_t bytes[16];
    char mnemonic[24];
    char text[80];

    bool is_branch;
    bool is_call;
    bool is_ret;
    bool is_conditional;
    uint64_t branch_target;

    bool reads_memory;
    bool writes_memory;

} E9Instruction;

/*
 * Multi-arch disassembler
 */
typedef struct E9Disasm E9Disasm;

E9Disasm *e9_disasm_create(E9Arch arch);
void e9_disasm_free(E9Disasm *dis);

int e9_disasm_one(E9Disasm *dis, const uint8_t *code, size_t size,
                  uint64_t address, E9Instruction *insn);

size_t e9_disasm_many(E9Disasm *dis, const uint8_t *code, size_t size,
                      uint64_t address, size_t count, E9Instruction **insns);

void e9_insns_free(E9Instruction *insns, size_t count);

/*
 * ============================================================================
 * Entropy Analysis
 * ============================================================================
 */

/*
 * Calculate Shannon entropy of data (0.0 - 8.0 for byte data)
 */
double e9_entropy(const uint8_t *data, size_t size);

/*
 * Entropy analysis result
 */
typedef struct {
    double *values;             /* Entropy per block */
    size_t num_blocks;
    size_t block_size;

    double min_entropy;
    double max_entropy;
    double avg_entropy;

    /* Detection flags */
    bool likely_compressed;     /* High entropy throughout */
    bool likely_encrypted;      /* Very high uniform entropy */
    bool has_padding;           /* Zero-entropy regions */

} E9EntropyResult;

E9EntropyResult *e9_entropy_analyze(const uint8_t *data, size_t size,
                                     size_t block_size);
void e9_entropy_free(E9EntropyResult *result);

/*
 * ============================================================================
 * String Extraction
 * ============================================================================
 */

/*
 * Extracted string
 */
typedef struct {
    uint64_t offset;
    char *value;
    size_t length;

    enum {
        E9_STR_ASCII,
        E9_STR_UTF8,
        E9_STR_UTF16LE,
        E9_STR_UTF16BE,
    } encoding;

    /* Heuristic classification */
    bool is_path;
    bool is_url;
    bool is_ip_addr;
    bool is_email;
    bool is_function_name;

} E9String;

/*
 * Extract printable strings
 */
E9String *e9_strings_extract(const uint8_t *data, size_t size,
                              size_t min_len, uint32_t *count);
void e9_strings_free(E9String *strings, uint32_t count);

/*
 * ============================================================================
 * Hash Computation
 * ============================================================================
 */

/*
 * Compute MD5 hash
 */
void e9_md5(const uint8_t *data, size_t size, uint8_t out[16]);

/*
 * Compute SHA-256 hash
 */
void e9_sha256(const uint8_t *data, size_t size, uint8_t out[32]);

/*
 * Format hash as hex string
 */
void e9_hash_to_hex(const uint8_t *hash, size_t len, char *out);

/*
 * ============================================================================
 * CRC Computation
 * ============================================================================
 */

uint32_t e9_crc32(const uint8_t *data, size_t size);
uint32_t e9_crc32_update(uint32_t crc, const uint8_t *data, size_t size);

/*
 * ============================================================================
 * Compression Detection
 * ============================================================================
 */

typedef enum {
    E9_COMPRESS_NONE = 0,
    E9_COMPRESS_ZLIB,
    E9_COMPRESS_GZIP,
    E9_COMPRESS_DEFLATE,
    E9_COMPRESS_BZIP2,
    E9_COMPRESS_LZMA,
    E9_COMPRESS_XZ,
    E9_COMPRESS_ZSTD,
    E9_COMPRESS_LZ4,
    E9_COMPRESS_LZO,
    E9_COMPRESS_UNKNOWN,
} E9CompressType;

/*
 * Detect compression type at offset
 */
E9CompressType e9_detect_compression(const uint8_t *data, size_t size);

/*
 * Get compression type name
 */
const char *e9_compress_name(E9CompressType type);

/*
 * ============================================================================
 * Utility Functions
 * ============================================================================
 */

/*
 * Hex dump
 */
void e9_hexdump(const uint8_t *data, size_t size, uint64_t base_addr,
                char *out, size_t out_size);

/*
 * Disassembly dump
 */
void e9_disasm_dump(E9Disasm *dis, const uint8_t *code, size_t size,
                    uint64_t address, char *out, size_t out_size);

/*
 * Pretty print binary info
 */
void e9_info_print(const E9BinaryInfo *info, char *out, size_t out_size);

/*
 * ============================================================================
 * Version Info
 * ============================================================================
 */

#define E9VENDOR_VERSION_MAJOR 1
#define E9VENDOR_VERSION_MINOR 0
#define E9VENDOR_VERSION_PATCH 0

const char *e9_vendor_version(void);
const char *e9_vendor_build_info(void);

#ifdef __cplusplus
}
#endif

#endif /* E9VENDOR_H */
