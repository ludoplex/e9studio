/*
 * e9compress.h
 * Compression/Encryption Detection and Handling
 *
 * Provides:
 * - Automatic compression format detection
 * - Streaming decompression for multiple formats
 * - Recompression for patched data
 * - Encryption detection and key inference hints
 * - Packed executable unwrapping
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

#ifndef E9COMPRESS_H
#define E9COMPRESS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Compression algorithms
 */
typedef enum {
    E9_COMP_NONE = 0,
    E9_COMP_DEFLATE,        /* zlib/gzip/zip deflate */
    E9_COMP_ZLIB,           /* zlib wrapper */
    E9_COMP_GZIP,           /* gzip wrapper */
    E9_COMP_BZIP2,
    E9_COMP_LZMA,           /* LZMA1 */
    E9_COMP_LZMA2,          /* LZMA2 (7z, xz) */
    E9_COMP_XZ,
    E9_COMP_ZSTD,
    E9_COMP_LZ4,
    E9_COMP_LZO,
    E9_COMP_BROTLI,
    E9_COMP_SNAPPY,
    E9_COMP_RLE,            /* Run-length encoding */
    E9_COMP_LZSS,           /* LZSS variants */
    E9_COMP_LZJB,           /* ZFS compression */
    E9_COMP_APLIB,          /* aPLib (common in packers) */
    E9_COMP_UCL,            /* UPX compression */
    E9_COMP_NRV,            /* UPX NRV variants */
    E9_COMP_JCALG1,         /* JCALG1 (Petite packer) */
    E9_COMP_CUSTOM,         /* Unknown/custom algorithm */
} E9CompressAlgo;

/*
 * Encryption algorithms
 */
typedef enum {
    E9_CRYPT_NONE = 0,
    E9_CRYPT_XOR,           /* Simple XOR */
    E9_CRYPT_XOR_ROLLING,   /* Rolling XOR key */
    E9_CRYPT_RC4,
    E9_CRYPT_AES_128,
    E9_CRYPT_AES_256,
    E9_CRYPT_CHACHA20,
    E9_CRYPT_BLOWFISH,
    E9_CRYPT_TEA,           /* Tiny Encryption Algorithm */
    E9_CRYPT_XTEA,
    E9_CRYPT_SERPENT,
    E9_CRYPT_TWOFISH,
    E9_CRYPT_CUSTOM,        /* Unknown/custom */
} E9CryptAlgo;

/*
 * Packer/protector types
 */
typedef enum {
    E9_PACK_NONE = 0,
    E9_PACK_UPX,
    E9_PACK_ASP,            /* ASPack */
    E9_PACK_FSG,
    E9_PACK_MEW,
    E9_PACK_MPRESS,
    E9_PACK_PECOMPACT,
    E9_PACK_PETITE,
    E9_PACK_NSPACK,
    E9_PACK_UPACK,
    E9_PACK_YODA,
    E9_PACK_KKRUNCHY,
    E9_PACK_TELOCK,
    E9_PACK_THEMIDA,
    E9_PACK_VMPROTECT,
    E9_PACK_ENIGMA,
    E9_PACK_OBSIDIUM,
    E9_PACK_ARMADILLO,
    E9_PACK_EXECRYPTOR,
    E9_PACK_CUSTOM,
} E9PackerType;

/*
 * Compression detection result
 */
typedef struct {
    E9CompressAlgo algorithm;
    uint64_t offset;            /* Start of compressed data */
    uint64_t compressed_size;
    uint64_t uncompressed_size; /* If known, 0 otherwise */
    float confidence;
    char description[128];

    /* Algorithm-specific metadata */
    union {
        struct {
            int window_bits;
            int level;
        } deflate;
        struct {
            uint32_t dict_size;
            int lc, lp, pb;     /* LZMA properties */
        } lzma;
        struct {
            int level;
        } zstd;
    } params;
} E9CompressInfo;

/*
 * Encryption detection result
 */
typedef struct {
    E9CryptAlgo algorithm;
    uint64_t offset;
    uint64_t size;
    float confidence;
    char description[128];

    /* Potential key information */
    bool key_found;
    uint8_t key[64];
    size_t key_length;
    uint64_t key_offset;        /* Where key might be stored */

    /* For XOR: detected key patterns */
    uint8_t xor_key[256];
    size_t xor_key_len;
    bool is_rolling_xor;
} E9CryptInfo;

/*
 * Packer detection result
 */
typedef struct {
    E9PackerType packer;
    char version[32];
    float confidence;

    /* Unpacking information */
    uint64_t oep_rva;           /* Original entry point (relative) */
    uint64_t oep_va;            /* Original entry point (virtual) */
    uint64_t packed_section;    /* RVA of packed data */
    uint64_t unpack_stub;       /* RVA of unpacking code */

    /* Layers */
    bool multi_layer;
    int num_layers;

    /* Anti-debugging/analysis */
    bool has_anti_debug;
    bool has_anti_vm;
    bool has_anti_dump;
    bool has_code_virt;         /* Code virtualization */
} E9PackerInfo;

/*
 * ============================================================================
 * Compression Detection
 * ============================================================================
 */

/*
 * Detect compression algorithm at offset
 */
E9CompressInfo e9_compress_detect(const uint8_t *data, size_t size, uint64_t offset);

/*
 * Scan for all compressed regions
 */
E9CompressInfo *e9_compress_scan(const uint8_t *data, size_t size, uint32_t *count);

/*
 * Get algorithm name
 */
const char *e9_compress_name(E9CompressAlgo algo);

/*
 * ============================================================================
 * Decompression
 * ============================================================================
 */

/*
 * Decompress data (auto-detect or specified algorithm)
 */
uint8_t *e9_decompress(const uint8_t *data, size_t size,
                       E9CompressAlgo algo, size_t *out_size);

/*
 * Decompress with callbacks (for streaming)
 */
typedef int (*E9DecompressCallback)(const uint8_t *chunk, size_t size, void *ctx);
int e9_decompress_stream(const uint8_t *data, size_t size,
                         E9CompressAlgo algo, E9DecompressCallback cb, void *ctx);

/*
 * ============================================================================
 * Recompression
 * ============================================================================
 */

/*
 * Recompress data
 */
uint8_t *e9_compress(const uint8_t *data, size_t size,
                     E9CompressAlgo algo, int level, size_t *out_size);

/*
 * Recompress to match original compressed size (for in-place patching)
 */
uint8_t *e9_compress_to_size(const uint8_t *data, size_t size,
                              E9CompressAlgo algo, size_t target_size,
                              size_t *out_size);

/*
 * ============================================================================
 * Encryption Detection
 * ============================================================================
 */

/*
 * Detect encryption at offset
 */
E9CryptInfo e9_crypt_detect(const uint8_t *data, size_t size, uint64_t offset);

/*
 * Scan for encrypted regions
 */
E9CryptInfo *e9_crypt_scan(const uint8_t *data, size_t size, uint32_t *count);

/*
 * Try to recover XOR key
 */
bool e9_crypt_recover_xor(const uint8_t *ciphertext, size_t size,
                          const uint8_t *known_plain, size_t plain_size,
                          uint8_t *key, size_t *key_len);

/*
 * Detect key in binary (looks for key schedules, constants)
 */
uint64_t e9_crypt_find_key(const uint8_t *data, size_t size,
                           E9CryptAlgo algo, uint8_t *key, size_t *key_len);

/*
 * Get algorithm name
 */
const char *e9_crypt_name(E9CryptAlgo algo);

/*
 * ============================================================================
 * Decryption
 * ============================================================================
 */

/*
 * Decrypt data
 */
uint8_t *e9_decrypt(const uint8_t *data, size_t size,
                    E9CryptAlgo algo, const uint8_t *key, size_t key_len,
                    size_t *out_size);

/*
 * Decrypt in-place
 */
int e9_decrypt_inplace(uint8_t *data, size_t size,
                       E9CryptAlgo algo, const uint8_t *key, size_t key_len);

/*
 * ============================================================================
 * Packer Detection
 * ============================================================================
 */

/*
 * Detect packer/protector
 */
E9PackerInfo e9_packer_detect(const uint8_t *data, size_t size);

/*
 * Get packer name
 */
const char *e9_packer_name(E9PackerType packer);

/*
 * ============================================================================
 * Unpacking
 * ============================================================================
 */

/*
 * Unpack executable (static unpacking for known packers)
 */
uint8_t *e9_unpack(const uint8_t *data, size_t size,
                   E9PackerType packer, size_t *out_size);

/*
 * Dynamic unpacking hints (find OEP, dump points)
 */
typedef struct {
    uint64_t oep;               /* Original entry point */
    uint64_t dump_address;      /* Best address to dump from */
    uint64_t dump_size;
    bool needs_imports;         /* IAT needs rebuilding */
    uint64_t iat_rva;
} E9UnpackHints;

E9UnpackHints e9_unpack_analyze(const uint8_t *data, size_t size, E9PackerInfo *info);

/*
 * ============================================================================
 * Specific Format Handlers
 * ============================================================================
 */

/* UPX unpacking */
uint8_t *e9_upx_unpack(const uint8_t *data, size_t size, size_t *out_size);
bool e9_upx_detect(const uint8_t *data, size_t size, char *version, size_t ver_size);

/* LZMA/LZMA2 */
uint8_t *e9_lzma_decompress(const uint8_t *data, size_t size, size_t *out_size);
uint8_t *e9_lzma_compress(const uint8_t *data, size_t size, int level, size_t *out_size);

/* Deflate/zlib/gzip */
uint8_t *e9_deflate_decompress(const uint8_t *data, size_t size, size_t *out_size);
uint8_t *e9_deflate_compress(const uint8_t *data, size_t size, int level, size_t *out_size);
uint8_t *e9_gzip_decompress(const uint8_t *data, size_t size, size_t *out_size);
uint8_t *e9_gzip_compress(const uint8_t *data, size_t size, int level, size_t *out_size);

/* Zstandard */
uint8_t *e9_zstd_decompress(const uint8_t *data, size_t size, size_t *out_size);
uint8_t *e9_zstd_compress(const uint8_t *data, size_t size, int level, size_t *out_size);

#ifdef __cplusplus
}
#endif

#endif /* E9COMPRESS_H */
