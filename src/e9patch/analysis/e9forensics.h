/*
 * e9forensics.h
 * Unified Binary Forensics and Deep Analysis
 *
 * Combines all analysis modules for comprehensive binary examination:
 * - Polyglot/schizophrenic detection (polyfile-inspired)
 * - Signature scanning (binwalk-inspired)
 * - Taint tracking and parser ID (polytracker-inspired)
 * - Compression/encryption handling
 * - Obfuscation detection/removal
 * - Memory editing and instrumentation
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

#ifndef E9FORENSICS_H
#define E9FORENSICS_H

#include "e9analysis.h"
#include "e9polyglot.h"
#include "e9compress.h"
#include "e9obfuscate.h"
#include "e9taint.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Comprehensive analysis report
 */
typedef struct {
    /* Binary identity */
    char filename[256];
    uint8_t sha256[32];
    uint8_t md5[16];
    size_t size;

    /* Format analysis */
    E9PolyglotAnalysis *polyglot;
    bool is_polyglot;
    bool is_packed;
    bool is_obfuscated;
    bool is_encrypted;

    /* Detected formats */
    E9FormatType primary_format;
    E9FormatType *embedded_formats;
    uint32_t num_embedded;

    /* Compression layers */
    E9CompressInfo *compression;
    uint32_t num_compressed;

    /* Encryption layers */
    E9CryptInfo *encryption;
    uint32_t num_encrypted;

    /* Packing */
    E9PackerInfo packer;

    /* Obfuscation */
    E9ObfuscationAnalysis *obfuscation;

    /* Parser/Taint analysis */
    E9TaintAnalysis *taint;

    /* Security assessment */
    struct {
        uint32_t total_vulns;
        uint32_t critical;
        uint32_t high;
        uint32_t medium;
        uint32_t low;

        bool has_nx;            /* Non-executable stack */
        bool has_pie;           /* Position independent */
        bool has_relro;         /* Read-only relocations */
        bool has_canary;        /* Stack canaries */
        bool has_fortify;       /* FORTIFY_SOURCE */

        char *notes;
    } security;

    /* Hidden data */
    E9HiddenRegion *hidden;
    uint32_t num_hidden;
    uint64_t total_hidden_size;

    /* Strings of interest */
    struct {
        char *value;
        uint64_t address;
        bool is_encrypted;
        char category[32];      /* e.g., "URL", "path", "command" */
    } *strings;
    uint32_t num_strings;

} E9ForensicsReport;

/*
 * Analysis options
 */
typedef struct {
    /* What to analyze */
    bool scan_signatures;
    bool detect_polyglot;
    bool detect_compression;
    bool detect_encryption;
    bool detect_packing;
    bool detect_obfuscation;
    bool run_taint_analysis;
    bool extract_strings;
    bool find_hidden_data;
    bool security_audit;

    /* Depth settings */
    bool recursive_extract;     /* Extract and analyze nested */
    int max_depth;              /* Maximum recursion depth */
    size_t max_extract_size;    /* Don't extract larger than this */

    /* Performance */
    bool fast_mode;             /* Skip expensive analysis */
    int num_threads;            /* Parallel analysis */

    /* Output */
    bool verbose;
    const char *output_dir;     /* For extracted files */

} E9ForensicsOptions;

/*
 * ============================================================================
 * Main Forensics API
 * ============================================================================
 */

/*
 * Run comprehensive forensic analysis
 */
E9ForensicsReport *e9_forensics_analyze(const uint8_t *data, size_t size,
                                         E9ForensicsOptions *opts);

/*
 * Analyze file by path
 */
E9ForensicsReport *e9_forensics_analyze_file(const char *path,
                                              E9ForensicsOptions *opts);

/*
 * Free report
 */
void e9_forensics_free(E9ForensicsReport *report);

/*
 * Get default options
 */
E9ForensicsOptions e9_forensics_default_options(void);

/*
 * ============================================================================
 * Report Generation
 * ============================================================================
 */

/*
 * Generate text report
 */
char *e9_forensics_report_text(E9ForensicsReport *report);

/*
 * Generate JSON report
 */
char *e9_forensics_report_json(E9ForensicsReport *report);

/*
 * Generate HTML report
 */
char *e9_forensics_report_html(E9ForensicsReport *report);

/*
 * Save report to file
 */
int e9_forensics_save_report(E9ForensicsReport *report,
                              const char *path, const char *format);

/*
 * ============================================================================
 * Extraction and Unpacking
 * ============================================================================
 */

/*
 * Extract all embedded content
 */
typedef struct {
    char name[256];
    E9FormatType format;
    uint64_t offset;
    uint64_t size;
    uint8_t *data;
    bool was_compressed;
    bool was_encrypted;
} E9ExtractedItem;

E9ExtractedItem *e9_forensics_extract_all(const uint8_t *data, size_t size,
                                           E9ForensicsReport *report,
                                           uint32_t *count);

/*
 * Unpack to original form
 */
uint8_t *e9_forensics_unpack(const uint8_t *data, size_t size,
                              E9ForensicsReport *report, size_t *out_size);

/*
 * Decompress all layers
 */
uint8_t *e9_forensics_decompress_all(const uint8_t *data, size_t size,
                                      E9ForensicsReport *report,
                                      size_t *out_size);

/*
 * Decrypt (if key found or provided)
 */
uint8_t *e9_forensics_decrypt(const uint8_t *data, size_t size,
                               E9ForensicsReport *report,
                               const uint8_t *key, size_t key_len,
                               size_t *out_size);

/*
 * ============================================================================
 * Memory Editing Support
 * ============================================================================
 */

/*
 * Memory edit operation
 */
typedef struct {
    uint64_t address;
    uint8_t *old_data;
    uint8_t *new_data;
    size_t size;
    char description[128];

    /* For undo */
    struct E9MemEdit *prev;
    struct E9MemEdit *next;
} E9MemEdit;

/*
 * Memory editing session
 */
typedef struct {
    E9Binary *binary;
    uint8_t *working_copy;      /* Modified copy */
    size_t working_size;

    E9MemEdit *edits;           /* Edit history */
    uint32_t num_edits;
    E9MemEdit *current;         /* For undo/redo */

    /* Constraints */
    bool preserve_format;       /* Keep format valid */
    bool preserve_checksums;    /* Update checksums */
    bool preserve_signatures;   /* Update code signatures */

} E9MemSession;

/*
 * Create memory editing session
 */
E9MemSession *e9_mem_session_create(const uint8_t *data, size_t size);

/*
 * Free session
 */
void e9_mem_session_free(E9MemSession *session);

/*
 * Apply edit
 */
int e9_mem_edit(E9MemSession *session, uint64_t addr,
                const uint8_t *data, size_t size, const char *desc);

/*
 * Undo/redo
 */
int e9_mem_undo(E9MemSession *session);
int e9_mem_redo(E9MemSession *session);

/*
 * Get modified data
 */
uint8_t *e9_mem_get_result(E9MemSession *session, size_t *out_size);

/*
 * Save modifications
 */
int e9_mem_save(E9MemSession *session, const char *path);

/*
 * ============================================================================
 * Debugging Instrumentation
 * ============================================================================
 */

/*
 * Instrumentation types
 */
typedef enum {
    E9_INST_TRACE,              /* Execution trace */
    E9_INST_COVERAGE,           /* Code coverage */
    E9_INST_TAINT,              /* Taint tracking */
    E9_INST_MEMORY,             /* Memory access logging */
    E9_INST_CALL,               /* Call tracing */
    E9_INST_HOOK,               /* Function hooking */
    E9_INST_CUSTOM,             /* Custom callback */
} E9InstrumentType;

/*
 * Instrumentation point
 */
typedef struct {
    E9InstrumentType type;
    uint64_t address;
    uint8_t *trampoline;
    size_t trampoline_size;

    /* For hooks */
    void (*callback)(void *ctx);
    void *context;

} E9InstrumentPoint;

/*
 * Generate instrumentation for binary
 */
E9InstrumentPoint *e9_forensics_instrument(E9Binary *bin,
                                            E9InstrumentType type,
                                            uint32_t *count);

/*
 * Generate e9patch JSON for instrumentation
 */
char *e9_forensics_gen_e9patch(E9Binary *bin, E9InstrumentType type);

/*
 * ============================================================================
 * Comparison and Diffing
 * ============================================================================
 */

/*
 * Binary diff result
 */
typedef struct {
    /* Changed regions */
    struct {
        uint64_t offset;
        uint64_t size;
        uint8_t *old_data;
        uint8_t *new_data;
        char change_type[32];   /* "modified", "inserted", "deleted" */
    } *changes;
    uint32_t num_changes;

    /* Semantic changes */
    struct {
        E9Function *func;
        char description[256];
    } *func_changes;
    uint32_t num_func_changes;

    /* Statistics */
    float similarity;           /* 0.0-1.0 */
    uint64_t bytes_added;
    uint64_t bytes_removed;
    uint64_t bytes_modified;

} E9BinaryDiff;

/*
 * Compare two binaries
 */
E9BinaryDiff *e9_forensics_diff(const uint8_t *old_data, size_t old_size,
                                 const uint8_t *new_data, size_t new_size);

/*
 * Free diff
 */
void e9_forensics_diff_free(E9BinaryDiff *diff);

/*
 * Apply diff to binary
 */
uint8_t *e9_forensics_patch(const uint8_t *data, size_t size,
                             E9BinaryDiff *diff, size_t *out_size);

/*
 * Generate patch file
 */
int e9_forensics_save_patch(E9BinaryDiff *diff, const char *path,
                             const char *format);

#ifdef __cplusplus
}
#endif

#endif /* E9FORENSICS_H */
