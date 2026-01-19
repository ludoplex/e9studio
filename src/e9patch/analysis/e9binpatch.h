/*
 * e9binpatch.h
 * In-place Binary Editing Pipeline
 *
 * Provides APIs for modifying binaries without full recompilation:
 * - Instruction patching (same-size and different-size)
 * - Trampoline insertion for larger patches
 * - Code cave discovery and utilization
 * - Binary rewriting with relocation fixup
 * - Support for ELF, PE, and Mach-O formats
 *
 * Integrates with decompiler for round-trip editing:
 *   binary -> decompile -> edit C -> recompile patch -> apply
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

#ifndef E9BINPATCH_H
#define E9BINPATCH_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "e9analysis.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * Patch Types (using E9Bin prefix to avoid conflict with e9analysis.h E9Patch)
 * ============================================================================
 */

typedef enum {
    E9_BINPATCH_BYTES,         /* Raw byte replacement */
    E9_BINPATCH_INSN,          /* Instruction replacement */
    E9_BINPATCH_NOP,           /* NOP out bytes/instructions */
    E9_BINPATCH_CALL,          /* Patch call target */
    E9_BINPATCH_JMP,           /* Patch jump target */
    E9_BINPATCH_TRAMPOLINE,    /* Insert trampoline to new code */
    E9_BINPATCH_HOOK,          /* Function hook (call + return) */
    E9_BINPATCH_DETOUR,        /* Full function detour */
} E9BinPatchType;

/*
 * Patch flags
 */
#define E9_BINPATCH_FLAG_BACKUP     0x0001  /* Create backup of original bytes */
#define E9_BINPATCH_FLAG_VERIFY     0x0002  /* Verify patch after applying */
#define E9_BINPATCH_FLAG_ATOMIC     0x0004  /* Atomic patch (for live patching) */
#define E9_BINPATCH_FLAG_CAVE       0x0008  /* Use code cave if available */
#define E9_BINPATCH_FLAG_EXTEND     0x0010  /* Extend section if needed */

/*
 * Section flags (ELF SHF_* compatible)
 */
#define E9_SECFLAG_WRITE    0x001
#define E9_SECFLAG_ALLOC    0x002
#define E9_SECFLAG_EXEC     0x004

/*
 * Single patch operation
 */
typedef struct E9BinPatch {
    E9BinPatchType type;
    uint32_t flags;

    /* Location */
    uint64_t address;           /* Virtual address to patch */
    uint64_t offset;            /* File offset (computed if 0) */
    size_t orig_size;           /* Original instruction/region size */

    /* New content */
    const uint8_t *new_bytes;   /* New bytes (for BYTES type) */
    size_t new_size;            /* Size of new content */

    /* For CALL/JMP/TRAMPOLINE */
    uint64_t target_addr;       /* Target address for branch */

    /* For HOOK/DETOUR */
    const uint8_t *hook_code;   /* Hook function code */
    size_t hook_code_size;

    /* Backup storage */
    uint8_t *backup_bytes;      /* Original bytes (if FLAG_BACKUP) */
    size_t backup_size;

    /* Metadata */
    const char *comment;        /* Human-readable description */
    int id;                     /* Unique patch ID */
} E9BinPatch;

/*
 * ============================================================================
 * Code Cave Management
 * ============================================================================
 */

/*
 * A code cave is an unused region in the binary where we can place new code
 */
typedef struct E9CodeCave {
    uint64_t address;           /* Virtual address */
    uint64_t offset;            /* File offset */
    size_t size;                /* Available size */
    bool writable;              /* Can write here */
    bool executable;            /* Is executable */
    int section_idx;            /* Which section (-1 = padding) */
} E9CodeCave;

/*
 * Code cave finder context
 */
typedef struct E9CaveFinder {
    E9Binary *bin;
    E9CodeCave *caves;
    size_t num_caves;
    size_t caves_capacity;

    /* Configuration */
    size_t min_cave_size;       /* Minimum size to consider (default 8) */
    uint8_t cave_byte;          /* Byte pattern to look for (default 0x00/0xCC) */
    bool include_padding;       /* Include inter-section padding */
    bool include_nop_sleds;     /* Include existing NOP sleds */
} E9CaveFinder;

/*
 * ============================================================================
 * Trampoline Generation
 * ============================================================================
 */

typedef enum {
    E9_TRAMP_JMP_REL32,         /* Relative 32-bit jump (x86-64) */
    E9_TRAMP_JMP_ABS64,         /* Absolute 64-bit jump (x86-64) */
    E9_TRAMP_B_REL26,           /* Relative branch (AArch64) */
    E9_TRAMP_LDR_BR,            /* Load + branch (AArch64, any distance) */
} E9TrampolineType;

typedef struct E9Trampoline {
    E9TrampolineType type;

    uint64_t from_addr;         /* Source address */
    uint64_t to_addr;           /* Target address */
    uint64_t cave_addr;         /* Code cave used (if any) */

    /* Generated trampoline code */
    uint8_t code[32];
    size_t code_size;

    /* For detours: relocated original instructions */
    uint8_t orig_insns[64];
    size_t orig_insns_size;
} E9Trampoline;

/*
 * ============================================================================
 * Patch Session
 * ============================================================================
 */

/*
 * A patch session manages multiple patches to a single binary
 */
typedef struct E9BinPatchSession {
    E9Binary *bin;              /* Target binary */

    /* Patches */
    E9BinPatch *patches;
    size_t num_patches;
    size_t patches_capacity;

    /* Code caves */
    E9CaveFinder *cave_finder;

    /* Trampolines */
    E9Trampoline *trampolines;
    size_t num_trampolines;
    size_t trampolines_capacity;

    /* New sections/segments added */
    struct {
        char name[16];
        uint64_t vaddr;
        uint64_t file_off;
        uint8_t *data;
        size_t size;
        uint32_t flags;
    } *new_sections;
    size_t num_new_sections;

    /* Output buffer */
    uint8_t *output;
    size_t output_size;
    size_t output_capacity;

    /* Status */
    bool finalized;
    int error_code;
    char error_msg[256];
} E9BinPatchSession;

/*
 * ============================================================================
 * API - Session Management
 * ============================================================================
 */

/*
 * Create a new patch session for a binary
 */
E9BinPatchSession *e9_binpatch_session_create(E9Binary *bin);

/*
 * Free patch session
 */
void e9_binpatch_session_free(E9BinPatchSession *session);

/*
 * ============================================================================
 * API - Patch Operations
 * ============================================================================
 */

/*
 * Add a raw byte patch
 */
int e9_binpatch_bytes(E9BinPatchSession *session, uint64_t addr,
                      const uint8_t *bytes, size_t size, uint32_t flags);

/*
 * NOP out bytes at address
 */
int e9_binpatch_nop(E9BinPatchSession *session, uint64_t addr, size_t size,
                    uint32_t flags);

/*
 * Replace instruction at address
 * If new instruction is smaller, remaining bytes are NOP'd
 * If larger, a trampoline is automatically created
 */
int e9_binpatch_insn(E9BinPatchSession *session, uint64_t addr,
                     const uint8_t *new_insn, size_t new_size, uint32_t flags);

/*
 * Patch a CALL instruction's target
 */
int e9_binpatch_call(E9BinPatchSession *session, uint64_t call_addr,
                     uint64_t new_target, uint32_t flags);

/*
 * Patch a JMP instruction's target
 */
int e9_binpatch_jmp(E9BinPatchSession *session, uint64_t jmp_addr,
                    uint64_t new_target, uint32_t flags);

/*
 * Insert a hook at function entry
 * Hook receives control before original function, can modify arguments
 */
int e9_binpatch_hook(E9BinPatchSession *session, uint64_t func_addr,
                     const uint8_t *hook_code, size_t hook_size, uint32_t flags);

/*
 * Detour a function to replacement
 * Original function is relocated and can be called from replacement
 */
int e9_binpatch_detour(E9BinPatchSession *session, uint64_t func_addr,
                       const uint8_t *new_func, size_t new_func_size,
                       uint64_t *orig_func_ptr, uint32_t flags);

/*
 * ============================================================================
 * API - Code Cave Management
 * ============================================================================
 */

/*
 * Find all code caves in binary
 */
int e9_caves_find(E9BinPatchSession *session, size_t min_size);

/*
 * Allocate space from code caves
 * Returns address of allocated space, or 0 on failure
 */
uint64_t e9_caves_alloc(E9BinPatchSession *session, size_t size, bool executable);

/*
 * Get list of found caves
 */
const E9CodeCave *e9_caves_list(E9BinPatchSession *session, size_t *count);

/*
 * ============================================================================
 * API - Finalization
 * ============================================================================
 */

/*
 * Apply all patches and generate output binary
 */
int e9_binpatch_apply(E9BinPatchSession *session);

/*
 * Write patched binary to file
 */
int e9_binpatch_write(E9BinPatchSession *session, const char *output_path);

/*
 * Get patched binary in memory
 */
const uint8_t *e9_binpatch_get_output(E9BinPatchSession *session, size_t *size);

/*
 * Generate patch summary (human-readable)
 */
char *e9_binpatch_summary(E9BinPatchSession *session);

/*
 * ============================================================================
 * API - Undo/Revert
 * ============================================================================
 */

/*
 * Revert a single patch (requires FLAG_BACKUP)
 */
int e9_binpatch_revert(E9BinPatchSession *session, int patch_id);

/*
 * Revert all patches
 */
int e9_binpatch_revert_all(E9BinPatchSession *session);

/*
 * ============================================================================
 * API - Validation
 * ============================================================================
 */

/*
 * Validate patches before applying
 * Checks for overlaps, relocation conflicts, etc.
 */
int e9_binpatch_validate(E9BinPatchSession *session);

/*
 * Verify patches after applying
 * Ensures bytes were written correctly
 */
int e9_binpatch_verify(E9BinPatchSession *session);

/*
 * ============================================================================
 * Helper Functions
 * ============================================================================
 */

/*
 * Calculate size of instruction at address
 */
size_t e9_binpatch_insn_size_at(E9Binary *bin, uint64_t addr);

/*
 * Check if address is within executable section
 */
bool e9_binpatch_addr_executable(E9Binary *bin, uint64_t addr);

/*
 * Convert virtual address to file offset
 */
uint64_t e9_binpatch_vaddr_to_offset(E9Binary *bin, uint64_t vaddr);

/*
 * Convert file offset to virtual address
 */
uint64_t e9_binpatch_offset_to_vaddr(E9Binary *bin, uint64_t offset);

/*
 * Generate NOP sled of given size for architecture
 */
void e9_binpatch_gen_nops(int arch, uint8_t *buf, size_t size);

/*
 * Generate jump instruction
 */
size_t e9_binpatch_gen_jmp(int arch, uint8_t *buf, uint64_t from, uint64_t to);

/*
 * Generate call instruction
 */
size_t e9_binpatch_gen_call(int arch, uint8_t *buf, uint64_t from, uint64_t to);

#ifdef __cplusplus
}
#endif

#endif /* E9BINPATCH_H */
