/*
 * e9polyglot.h
 * Polyglot and Schizophrenic File Detection
 *
 * Inspired by polyfile's approach to identifying files that are
 * simultaneously valid in multiple formats (polyglots) or contain
 * conflicting/ambiguous structures (schizophrenic files).
 *
 * Key concepts:
 * - Polyglot: File valid as multiple formats (e.g., APE is DOS+ELF+PE+shell)
 * - Schizophrenic: File with conflicting parseable regions
 * - Chimera: File with grafted sections from different formats
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

#ifndef E9POLYGLOT_H
#define E9POLYGLOT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Known file format types
 */
typedef enum {
    E9_FMT_UNKNOWN = 0,

    /* Executables */
    E9_FMT_ELF,
    E9_FMT_PE,
    E9_FMT_MACHO,
    E9_FMT_DOS_MZ,
    E9_FMT_DOS_COM,
    E9_FMT_SHELL_SCRIPT,
    E9_FMT_APE,             /* Actually Portable Executable (polyglot) */

    /* Archives */
    E9_FMT_ZIP,
    E9_FMT_GZIP,
    E9_FMT_BZIP2,
    E9_FMT_XZ,
    E9_FMT_ZSTD,
    E9_FMT_LZ4,
    E9_FMT_TAR,
    E9_FMT_CPIO,
    E9_FMT_AR,
    E9_FMT_7Z,
    E9_FMT_RAR,

    /* Firmware/ROM */
    E9_FMT_SQUASHFS,
    E9_FMT_CRAMFS,
    E9_FMT_JFFS2,
    E9_FMT_UBIFS,
    E9_FMT_EXT4,
    E9_FMT_FAT,
    E9_FMT_ISO9660,

    /* Images */
    E9_FMT_PNG,
    E9_FMT_JPEG,
    E9_FMT_GIF,
    E9_FMT_BMP,
    E9_FMT_PDF,

    /* Documents */
    E9_FMT_XML,
    E9_FMT_HTML,
    E9_FMT_JSON,

    /* Bytecode/IR */
    E9_FMT_WASM,
    E9_FMT_JAVA_CLASS,
    E9_FMT_DEX,
    E9_FMT_LLVM_BC,

    /* Crypto/Keys */
    E9_FMT_PEM,
    E9_FMT_DER,
    E9_FMT_PGP,

    /* Custom/Special */
    E9_FMT_ZIPOS,           /* Cosmopolitan ZipOS */
    E9_FMT_APPIMAGE,
    E9_FMT_FLATPAK,
    E9_FMT_SNAP,

    E9_FMT_COUNT
} E9FormatType;

/*
 * Format interpretation at a specific region
 */
typedef struct E9FormatRegion {
    E9FormatType format;
    uint64_t offset;        /* Start offset in file */
    uint64_t size;          /* Size of this region */
    uint64_t vaddr;         /* Virtual address if applicable */

    /* Interpretation details */
    char description[256];  /* Human-readable description */
    float confidence;       /* 0.0-1.0 confidence score */

    /* Nested formats (e.g., ZIP inside ELF) */
    struct E9FormatRegion *children;
    uint32_t num_children;

    /* Conflicts with other interpretations */
    struct E9FormatRegion *conflicts;
    uint32_t num_conflicts;

    struct E9FormatRegion *next;
} E9FormatRegion;

/*
 * Polyglot analysis result
 */
typedef struct {
    /* Primary interpretations (what the file "is") */
    E9FormatRegion *interpretations;
    uint32_t num_interpretations;

    /* Is this a known polyglot type? */
    bool is_polyglot;
    bool is_schizophrenic;
    bool is_chimera;

    /* APE-specific analysis */
    bool is_ape;
    struct {
        uint64_t mz_header;         /* DOS MZ header offset */
        uint64_t elf_header;        /* ELF header offset */
        uint64_t pe_header;         /* PE header offset */
        uint64_t shell_shebang;     /* Shell script start */
        uint64_t zipos_start;       /* ZipOS central directory */
        uint64_t zipos_end;
    } ape_layout;

    /* Embedded content */
    E9FormatRegion *embedded;
    uint32_t num_embedded;

    /* Parser attack surface */
    struct {
        uint32_t num_parsers;       /* Number of distinct parsers triggered */
        uint32_t ambiguous_regions; /* Regions with multiple valid parses */
        uint32_t hidden_data;       /* Data not covered by any format */
    } attack_surface;

} E9PolyglotAnalysis;

/*
 * Magic signature entry
 */
typedef struct {
    E9FormatType format;
    const char *name;
    const uint8_t *magic;
    size_t magic_len;
    int64_t offset;         /* Offset from start (-1 for any, -2 for EOF-relative) */
    const char *description;
} E9MagicSignature;

/*
 * ============================================================================
 * Polyglot Detection API
 * ============================================================================
 */

/*
 * Analyze file for polyglot/schizophrenic properties
 */
E9PolyglotAnalysis *e9_polyglot_analyze(const uint8_t *data, size_t size);

/*
 * Free analysis result
 */
void e9_polyglot_free(E9PolyglotAnalysis *analysis);

/*
 * Get all valid interpretations at a specific offset
 */
E9FormatRegion *e9_polyglot_at_offset(E9PolyglotAnalysis *analysis, uint64_t offset);

/*
 * Check if file is a specific polyglot type
 */
bool e9_is_ape(const uint8_t *data, size_t size);
bool e9_is_polyglot_pdf(const uint8_t *data, size_t size);
bool e9_is_polyglot_zip(const uint8_t *data, size_t size);

/*
 * Get format name string
 */
const char *e9_format_name(E9FormatType fmt);

/*
 * ============================================================================
 * Signature Scanning (binwalk-inspired)
 * ============================================================================
 */

/*
 * Scan for all known signatures
 */
E9FormatRegion *e9_signature_scan(const uint8_t *data, size_t size);

/*
 * Scan for specific format
 */
E9FormatRegion *e9_signature_scan_format(const uint8_t *data, size_t size,
                                          E9FormatType format);

/*
 * Add custom signature
 */
int e9_signature_add(const E9MagicSignature *sig);

/*
 * Get built-in signature database
 */
const E9MagicSignature *e9_signature_database(size_t *count);

/*
 * ============================================================================
 * Entropy Analysis
 * ============================================================================
 */

typedef struct {
    double entropy;         /* Shannon entropy (0-8 for bytes) */
    double chi_square;      /* Chi-square statistic */
    bool likely_compressed; /* Entropy > 7.5 */
    bool likely_encrypted;  /* Entropy > 7.9 and random distribution */
    bool likely_text;       /* Low entropy, printable chars */
} E9EntropyResult;

/*
 * Calculate entropy of a region
 */
E9EntropyResult e9_entropy_analyze(const uint8_t *data, size_t size);

/*
 * Generate entropy map (entropy per block)
 */
double *e9_entropy_map(const uint8_t *data, size_t size,
                       size_t block_size, size_t *num_blocks);

/*
 * Find high-entropy regions (likely compressed/encrypted)
 */
E9FormatRegion *e9_entropy_find_high(const uint8_t *data, size_t size,
                                      double threshold);

/*
 * ============================================================================
 * APE-Specific Analysis
 * ============================================================================
 */

/*
 * Parse APE file structure
 */
typedef struct {
    /* DOS stub */
    uint64_t dos_header;
    uint64_t dos_stub_size;

    /* ELF component */
    uint64_t elf_offset;
    uint64_t elf_size;
    uint64_t elf_entry;
    uint64_t elf_phdr;
    uint64_t elf_shdr;

    /* PE component */
    uint64_t pe_offset;
    uint64_t pe_size;
    uint64_t pe_entry;
    uint64_t pe_sections;

    /* Shell script component */
    uint64_t shell_offset;
    uint64_t shell_size;

    /* Mach-O component (if present) */
    uint64_t macho_offset;
    uint64_t macho_size;

    /* ZipOS */
    uint64_t zipos_start;
    uint64_t zipos_central_dir;
    uint64_t zipos_end;
    uint32_t zipos_num_entries;

    /* Assimilated sections (modified at runtime) */
    uint64_t assimilate_offset;
    uint64_t assimilate_size;

} E9APELayout;

int e9_ape_parse(const uint8_t *data, size_t size, E9APELayout *layout);

/*
 * Extract component from APE
 */
uint8_t *e9_ape_extract_elf(const uint8_t *data, size_t size, size_t *out_size);
uint8_t *e9_ape_extract_pe(const uint8_t *data, size_t size, size_t *out_size);
uint8_t *e9_ape_extract_zipos(const uint8_t *data, size_t size, size_t *out_size);

/*
 * ============================================================================
 * Hidden Data Detection
 * ============================================================================
 */

typedef struct {
    uint64_t offset;
    uint64_t size;
    char description[128];
    E9EntropyResult entropy;
} E9HiddenRegion;

/*
 * Find regions not covered by any format structure
 */
E9HiddenRegion *e9_find_hidden(const uint8_t *data, size_t size,
                                E9PolyglotAnalysis *analysis,
                                uint32_t *num_regions);

/*
 * Find data appended after format end
 */
E9HiddenRegion *e9_find_appended(const uint8_t *data, size_t size,
                                  E9FormatType primary_format,
                                  uint32_t *num_regions);

/*
 * Find data in format slack space
 */
E9HiddenRegion *e9_find_slack(const uint8_t *data, size_t size,
                               E9FormatType format,
                               uint32_t *num_regions);

#ifdef __cplusplus
}
#endif

#endif /* E9POLYGLOT_H */
