/*
 * e9taint.h
 * Taint Tracking and Parser Identification Engine
 *
 * Inspired by polytracker's approach to understanding how input
 * data flows through a program, enabling identification of:
 * - Parser entry points
 * - Format handling logic
 * - Input validation routines
 * - Data transformation functions
 *
 * This uses static analysis approximations rather than dynamic
 * instrumentation, making it suitable for binary analysis without
 * execution.
 *
 * Key concepts:
 * - Taint source: Where untrusted data enters (file read, network recv)
 * - Taint sink: Security-sensitive operations (exec, write, alloc)
 * - Taint propagation: How data flows through computations
 * - Parser detection: Functions that branch on input bytes
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

#ifndef E9TAINT_H
#define E9TAINT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "e9analysis.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Taint source types
 */
typedef enum {
    E9_TAINT_SRC_UNKNOWN = 0,

    /* File I/O */
    E9_TAINT_SRC_FILE_READ,     /* read(), fread(), etc. */
    E9_TAINT_SRC_FILE_MMAP,     /* mmap() of file */
    E9_TAINT_SRC_FILE_ARGV,     /* Command line arguments */
    E9_TAINT_SRC_FILE_ENVP,     /* Environment variables */

    /* Network */
    E9_TAINT_SRC_NET_RECV,      /* recv(), recvfrom() */
    E9_TAINT_SRC_NET_READ,      /* read() on socket */

    /* User input */
    E9_TAINT_SRC_STDIN,         /* stdin input */
    E9_TAINT_SRC_GUI,           /* GUI input events */

    /* IPC */
    E9_TAINT_SRC_PIPE,          /* Pipe read */
    E9_TAINT_SRC_SHM,           /* Shared memory */
    E9_TAINT_SRC_MSG,           /* Message queues */

    /* Other */
    E9_TAINT_SRC_CUSTOM,

} E9TaintSourceType;

/*
 * Taint sink types (security-sensitive operations)
 */
typedef enum {
    E9_TAINT_SINK_UNKNOWN = 0,

    /* Code execution */
    E9_TAINT_SINK_EXEC,         /* exec family */
    E9_TAINT_SINK_SYSTEM,       /* system() */
    E9_TAINT_SINK_DLOPEN,       /* dlopen() */
    E9_TAINT_SINK_JIT,          /* JIT compilation */

    /* Memory */
    E9_TAINT_SINK_ALLOC_SIZE,   /* malloc() size argument */
    E9_TAINT_SINK_MEMCPY_SIZE,  /* memcpy() size argument */
    E9_TAINT_SINK_BUFFER_IDX,   /* Array index */
    E9_TAINT_SINK_FORMAT_STR,   /* printf() format string */

    /* File system */
    E9_TAINT_SINK_FILE_PATH,    /* open() path argument */
    E9_TAINT_SINK_FILE_WRITE,   /* write() to file */
    E9_TAINT_SINK_UNLINK,       /* unlink() */

    /* Network */
    E9_TAINT_SINK_NET_SEND,     /* send() */
    E9_TAINT_SINK_CONNECT,      /* connect() address */
    E9_TAINT_SINK_SQL_QUERY,    /* SQL query string */

    /* Control flow */
    E9_TAINT_SINK_INDIRECT_JMP, /* Indirect jump target */
    E9_TAINT_SINK_INDIRECT_CALL,/* Indirect call target */
    E9_TAINT_SINK_RET_ADDR,     /* Return address */

} E9TaintSinkType;

/*
 * Taint label - tracks which input bytes affect a value
 */
typedef struct {
    uint32_t source_id;         /* Source identifier */
    uint64_t byte_offset;       /* Offset in input */
    uint32_t byte_count;        /* Number of bytes */
} E9TaintLabel;

/*
 * Tainted location in the program
 */
typedef struct E9TaintLocation {
    uint64_t address;           /* Code address */
    int operand;                /* Which operand (0=dst, 1=src1, etc.) */

    E9TaintLabel *labels;       /* Labels affecting this location */
    uint32_t num_labels;

    /* What transformation was applied */
    enum {
        E9_TAINT_XFORM_NONE,
        E9_TAINT_XFORM_COPY,
        E9_TAINT_XFORM_ARITH,
        E9_TAINT_XFORM_BITWISE,
        E9_TAINT_XFORM_COMPARE,
        E9_TAINT_XFORM_LOOKUP,  /* Table lookup */
    } transform;

    struct E9TaintLocation *next;
} E9TaintLocation;

/*
 * Taint source instance
 */
typedef struct {
    E9TaintSourceType type;
    uint64_t call_site;         /* Where the source function is called */
    uint64_t buffer_addr;       /* Where data is stored (if known) */
    uint64_t buffer_size;       /* Size of input (if known) */

    /* For file sources */
    char filename[256];

    /* For network sources */
    uint32_t socket_fd;

    /* Tracking ID */
    uint32_t source_id;

} E9TaintSource;

/*
 * Taint sink instance
 */
typedef struct {
    E9TaintSinkType type;
    uint64_t address;           /* Where the sink is */
    int argument;               /* Which argument is tainted */

    E9TaintLabel *labels;       /* What input affects this sink */
    uint32_t num_labels;

    /* Severity */
    enum {
        E9_SEVERITY_INFO,
        E9_SEVERITY_LOW,
        E9_SEVERITY_MEDIUM,
        E9_SEVERITY_HIGH,
        E9_SEVERITY_CRITICAL,
    } severity;

    char description[256];

} E9TaintSink;

/*
 * Parser function detection
 */
typedef struct {
    E9Function *func;
    uint64_t address;
    char name[128];

    /* Parser characteristics */
    uint32_t input_branches;    /* Branches depending on input */
    uint32_t byte_comparisons;  /* Number of byte comparisons */
    uint32_t magic_checks;      /* Magic number comparisons */
    uint32_t length_checks;     /* Size/length validations */
    uint32_t bound_checks;      /* Bounds checking */

    /* What format it parses (inferred) */
    struct {
        char format_name[64];   /* e.g., "PNG", "ELF", "JSON" */
        float confidence;
    } inferred_format;

    /* Input byte dependencies */
    struct {
        uint64_t byte_offset;   /* Input byte position */
        uint64_t branch_addr;   /* Where it affects control flow */
        uint8_t compared_value; /* What value it's compared against */
    } *byte_deps;
    uint32_t num_deps;

    /* Call graph position */
    bool is_entry;              /* Called with raw input */
    bool is_leaf;               /* Doesn't call other parsers */
    uint32_t depth;             /* Nesting depth in parser hierarchy */

} E9ParserFunc;

/*
 * Full taint analysis result
 */
typedef struct {
    /* Sources and sinks */
    E9TaintSource *sources;
    uint32_t num_sources;

    E9TaintSink *sinks;
    uint32_t num_sinks;

    /* Data flow paths (source to sink) */
    struct {
        E9TaintSource *source;
        E9TaintSink *sink;
        E9TaintLocation *path;  /* Intermediate locations */
        uint32_t path_len;
    } *flows;
    uint32_t num_flows;

    /* Detected parsers */
    E9ParserFunc *parsers;
    uint32_t num_parsers;

    /* Summary */
    uint32_t total_tainted_locs;
    uint32_t critical_sinks;
    bool has_format_string_vuln;
    bool has_buffer_overflow;
    bool has_command_injection;

} E9TaintAnalysis;

/*
 * ============================================================================
 * Taint Analysis API
 * ============================================================================
 */

/*
 * Create taint analysis context
 */
E9TaintAnalysis *e9_taint_create(E9Binary *bin);

/*
 * Free taint analysis
 */
void e9_taint_free(E9TaintAnalysis *analysis);

/*
 * Run full taint analysis
 */
int e9_taint_analyze(E9TaintAnalysis *analysis);

/*
 * ============================================================================
 * Source/Sink Detection
 * ============================================================================
 */

/*
 * Find all taint sources in binary
 */
E9TaintSource *e9_taint_find_sources(E9Binary *bin, uint32_t *count);

/*
 * Find all taint sinks in binary
 */
E9TaintSink *e9_taint_find_sinks(E9Binary *bin, uint32_t *count);

/*
 * Mark custom source/sink
 */
int e9_taint_add_source(E9TaintAnalysis *analysis, uint64_t addr,
                        E9TaintSourceType type);
int e9_taint_add_sink(E9TaintAnalysis *analysis, uint64_t addr,
                      E9TaintSinkType type);

/*
 * ============================================================================
 * Taint Propagation
 * ============================================================================
 */

/*
 * Propagation rules for instructions
 */
typedef enum {
    E9_PROP_NONE,           /* No propagation */
    E9_PROP_COPY,           /* dst = src (copy taint) */
    E9_PROP_MERGE,          /* dst = src1 op src2 (merge taints) */
    E9_PROP_SPREAD,         /* Taint spreads to all dests */
    E9_PROP_CLEAR,          /* Taint is cleared */
} E9PropRule;

/*
 * Get propagation rule for instruction
 */
E9PropRule e9_taint_prop_rule(E9Instruction *insn);

/*
 * Propagate taint through function
 */
int e9_taint_propagate_func(E9TaintAnalysis *analysis, E9Function *func);

/*
 * Propagate taint through basic block
 */
int e9_taint_propagate_block(E9TaintAnalysis *analysis, E9BasicBlock *block);

/*
 * ============================================================================
 * Parser Detection
 * ============================================================================
 */

/*
 * Detect parser functions
 */
E9ParserFunc *e9_taint_find_parsers(E9Binary *bin, uint32_t *count);

/*
 * Analyze single function for parser patterns
 */
E9ParserFunc *e9_taint_analyze_parser(E9Binary *bin, E9Function *func);

/*
 * Detect magic number comparisons (format identification)
 */
typedef struct {
    uint64_t address;           /* Comparison instruction */
    uint64_t value;             /* Magic value */
    size_t size;                /* Size of comparison (1,2,4,8) */
    bool is_string;             /* String comparison? */
    char format_hint[32];       /* e.g., "ELF", "PNG" based on magic */
} E9MagicCheck;

E9MagicCheck *e9_taint_find_magic_checks(E9Binary *bin, uint32_t *count);

/*
 * ============================================================================
 * Format Recovery
 * ============================================================================
 */

/*
 * Inferred field in parsed format
 */
typedef struct {
    uint64_t offset;            /* Offset in input */
    uint64_t size;              /* Size of field */
    char name[64];              /* Inferred name */

    enum {
        E9_FIELD_MAGIC,         /* Magic number */
        E9_FIELD_LENGTH,        /* Length/size field */
        E9_FIELD_OFFSET,        /* Offset/pointer */
        E9_FIELD_COUNT,         /* Array count */
        E9_FIELD_FLAGS,         /* Bit flags */
        E9_FIELD_ENUM,          /* Enumeration */
        E9_FIELD_STRING,        /* String data */
        E9_FIELD_DATA,          /* Opaque data */
    } type;

    /* Constraints discovered */
    bool has_min;
    bool has_max;
    uint64_t min_value;
    uint64_t max_value;
    uint64_t *valid_values;     /* For enums */
    uint32_t num_valid;

} E9InferredField;

/*
 * Inferred format structure
 */
typedef struct {
    char name[64];              /* Format name (if detected) */
    E9InferredField *fields;
    uint32_t num_fields;

    /* Relationships */
    struct {
        uint32_t length_field;  /* Which field holds length */
        uint32_t data_field;    /* Which field is variable data */
    } *len_data_pairs;
    uint32_t num_pairs;

} E9InferredFormat;

/*
 * Infer format structure from parser analysis
 */
E9InferredFormat *e9_taint_infer_format(E9TaintAnalysis *analysis);

/*
 * Generate format specification (kaitai-struct style)
 */
char *e9_taint_generate_spec(E9InferredFormat *format);

/*
 * ============================================================================
 * Data Flow Queries
 * ============================================================================
 */

/*
 * Find all paths from input byte to instruction
 */
E9TaintLocation *e9_taint_find_paths(E9TaintAnalysis *analysis,
                                      uint64_t input_offset,
                                      uint64_t target_addr);

/*
 * Find all instructions affected by input byte range
 */
E9TaintLocation *e9_taint_affected_by(E9TaintAnalysis *analysis,
                                       uint64_t offset, uint64_t size);

/*
 * Find which input bytes affect an instruction
 */
E9TaintLabel *e9_taint_deps_of(E9TaintAnalysis *analysis,
                                uint64_t addr, uint32_t *count);

/*
 * ============================================================================
 * Visualization
 * ============================================================================
 */

/*
 * Generate taint flow graph (DOT format)
 */
int e9_taint_to_dot(E9TaintAnalysis *analysis, const char *path);

/*
 * Generate parser call hierarchy
 */
int e9_taint_parser_hierarchy(E9TaintAnalysis *analysis, const char *path);

/*
 * Generate byte dependency map
 */
int e9_taint_byte_map(E9TaintAnalysis *analysis, const char *path);

/*
 * ============================================================================
 * Instrumentation Generation
 * ============================================================================
 */

/*
 * Generate e9patch instrumentation for dynamic taint tracking
 */
char *e9_taint_gen_instrument(E9Binary *bin, E9TaintSource *source);

/*
 * Generate taint tracking trampoline code
 */
uint8_t *e9_taint_gen_trampoline(E9Binary *bin, uint64_t addr,
                                  size_t *out_size);

/*
 * ============================================================================
 * Known API Signatures
 * ============================================================================
 */

/*
 * API function taint behavior
 */
typedef struct {
    const char *name;
    E9TaintSourceType source;   /* If this is a source */
    E9TaintSinkType sink;       /* If this is a sink */
    int tainted_arg;            /* Which arg receives taint (-1 = return) */
    int taint_size_arg;         /* Which arg determines taint size */
} E9APITaintSig;

/*
 * Get built-in API signatures
 */
const E9APITaintSig *e9_taint_api_signatures(size_t *count);

/*
 * Add custom API signature
 */
int e9_taint_add_api_sig(const E9APITaintSig *sig);

#ifdef __cplusplus
}
#endif

#endif /* E9TAINT_H */
