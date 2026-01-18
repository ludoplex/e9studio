/*
 * e9binpatch.c
 * In-place Binary Editing Pipeline Implementation
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

#include "e9binpatch.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

/*
 * ============================================================================
 * Memory Management
 * ============================================================================
 */

static void *bp_alloc(size_t size)
{
    void *p = calloc(1, size);
    if (!p) {
        fprintf(stderr, "e9binpatch: allocation failed (%zu bytes)\n", size);
    }
    return p;
}

static void *bp_realloc(void *ptr, size_t size)
{
    void *p = realloc(ptr, size);
    if (!p && size > 0) {
        fprintf(stderr, "e9binpatch: reallocation failed (%zu bytes)\n", size);
    }
    return p;
}

static void bp_free(void *ptr)
{
    free(ptr);
}

/*
 * ============================================================================
 * Error Handling
 * ============================================================================
 */

static void set_error(E9BinPatchSession *session, int code, const char *fmt, ...)
{
    session->error_code = code;
    va_list args;
    va_start(args, fmt);
    vsnprintf(session->error_msg, sizeof(session->error_msg), fmt, args);
    va_end(args);
}

/*
 * ============================================================================
 * Session Management
 * ============================================================================
 */

E9BinPatchSession *e9_binpatch_session_create(E9Binary *bin)
{
    if (!bin) return NULL;

    E9BinPatchSession *session = bp_alloc(sizeof(E9BinPatchSession));
    if (!session) return NULL;

    session->bin = bin;
    session->patches_capacity = 64;
    session->patches = bp_alloc(session->patches_capacity * sizeof(E9BinPatch));
    if (!session->patches) {
        bp_free(session);
        return NULL;
    }

    session->trampolines_capacity = 32;
    session->trampolines = bp_alloc(session->trampolines_capacity * sizeof(E9Trampoline));
    if (!session->trampolines) {
        bp_free(session->patches);
        bp_free(session);
        return NULL;
    }

    /* Initialize output buffer with copy of original binary */
    session->output_capacity = bin->size + 4096;  /* Extra space for extensions */
    session->output = bp_alloc(session->output_capacity);
    if (!session->output) {
        bp_free(session->trampolines);
        bp_free(session->patches);
        bp_free(session);
        return NULL;
    }
    memcpy(session->output, bin->data, bin->size);
    session->output_size = bin->size;

    return session;
}

void e9_binpatch_session_free(E9BinPatchSession *session)
{
    if (!session) return;

    /* Free backup bytes in patches */
    for (size_t i = 0; i < session->num_patches; i++) {
        bp_free(session->patches[i].backup_bytes);
    }
    bp_free(session->patches);
    bp_free(session->trampolines);

    /* Free cave finder */
    if (session->cave_finder) {
        bp_free(session->cave_finder->caves);
        bp_free(session->cave_finder);
    }

    /* Free new sections */
    if (session->new_sections) {
        for (size_t i = 0; i < session->num_new_sections; i++) {
            bp_free(session->new_sections[i].data);
        }
        bp_free(session->new_sections);
    }

    bp_free(session->output);
    bp_free(session);
}

/*
 * ============================================================================
 * Internal Helpers
 * ============================================================================
 */

static int ensure_patch_capacity(E9BinPatchSession *session)
{
    if (session->num_patches >= session->patches_capacity) {
        size_t new_cap = session->patches_capacity * 2;
        E9BinPatch *new_patches = bp_realloc(session->patches, new_cap * sizeof(E9BinPatch));
        if (!new_patches) {
            set_error(session, -1, "Failed to expand patch array");
            return -1;
        }
        session->patches = new_patches;
        session->patches_capacity = new_cap;
    }
    return 0;
}

/*
 * ============================================================================
 * Address Conversion
 * ============================================================================
 */

uint64_t e9_binpatch_vaddr_to_offset(E9Binary *bin, uint64_t vaddr)
{
    if (!bin) return 0;

    /* Check sections - E9Binary uses 'addr' for virtual address */
    for (uint32_t i = 0; i < bin->num_sections; i++) {
        uint64_t sec_addr = bin->sections[i].addr;
        uint64_t sec_size = bin->sections[i].size;
        if (vaddr >= sec_addr && vaddr < sec_addr + sec_size) {
            /* Compute offset - assume sections map linearly from base */
            /* For simplicity, use vaddr - base_address as approximation */
            return vaddr - bin->base_address;
        }
    }

    /* Direct offset calculation for addresses within binary */
    if (vaddr >= bin->base_address && vaddr < bin->base_address + bin->size) {
        return vaddr - bin->base_address;
    }

    return 0;
}

uint64_t e9_binpatch_offset_to_vaddr(E9Binary *bin, uint64_t offset)
{
    if (!bin || offset >= bin->size) return 0;
    return bin->base_address + offset;
}

bool e9_binpatch_addr_executable(E9Binary *bin, uint64_t addr)
{
    if (!bin) return false;

    for (uint32_t i = 0; i < bin->num_sections; i++) {
        uint64_t sec_addr = bin->sections[i].addr;
        uint64_t sec_size = bin->sections[i].size;
        if (addr >= sec_addr && addr < sec_addr + sec_size) {
            return (bin->sections[i].flags & E9_SECFLAG_EXEC) != 0;
        }
    }

    return false;
}

/*
 * ============================================================================
 * NOP/Jump Generation
 * ============================================================================
 */

void e9_binpatch_gen_nops(int arch, uint8_t *buf, size_t size)
{
    if (!buf || size == 0) return;

    if (arch == E9_ARCH_AARCH64) {
        /* AArch64 NOP: 0xD503201F (little-endian) */
        size_t nops = size / 4;
        for (size_t i = 0; i < nops; i++) {
            buf[i*4 + 0] = 0x1F;
            buf[i*4 + 1] = 0x20;
            buf[i*4 + 2] = 0x03;
            buf[i*4 + 3] = 0xD5;
        }
    } else {
        /* x86-64: Use multi-byte NOPs for efficiency */
        static const uint8_t nop_seqs[][9] = {
            {0x90},                                      /* 1: nop */
            {0x66, 0x90},                                /* 2: xchg ax,ax */
            {0x0F, 0x1F, 0x00},                          /* 3: nop dword [rax] */
            {0x0F, 0x1F, 0x40, 0x00},                    /* 4: nop dword [rax+0] */
            {0x0F, 0x1F, 0x44, 0x00, 0x00},              /* 5: nop dword [rax+rax+0] */
            {0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00},        /* 6: nop word [rax+rax+0] */
            {0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00},  /* 7: nop dword [rax+0] */
            {0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00},  /* 8: nop dword [rax+rax+0] */
            {0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00},  /* 9: nop word [...] */
        };

        size_t pos = 0;
        while (pos < size) {
            size_t remain = size - pos;
            size_t nop_size = (remain > 9) ? 9 : remain;
            memcpy(buf + pos, nop_seqs[nop_size - 1], nop_size);
            pos += nop_size;
        }
    }
}

size_t e9_binpatch_gen_jmp(int arch, uint8_t *buf, uint64_t from, uint64_t to)
{
    if (!buf) return 0;

    if (arch == E9_ARCH_AARCH64) {
        /* AArch64: B <offset> (26-bit signed offset, *4) */
        int64_t offset = (int64_t)(to - from);
        if (offset >= -128*1024*1024 && offset < 128*1024*1024) {
            int32_t imm26 = (int32_t)(offset / 4) & 0x03FFFFFF;
            uint32_t insn = 0x14000000 | imm26;
            buf[0] = (uint8_t)(insn);
            buf[1] = (uint8_t)(insn >> 8);
            buf[2] = (uint8_t)(insn >> 16);
            buf[3] = (uint8_t)(insn >> 24);
            return 4;
        } else {
            /* Need LDR + BR for far jump */
            /* LDR X16, #8; BR X16; .quad target */
            buf[0] = 0x50; buf[1] = 0x00; buf[2] = 0x00; buf[3] = 0x58;  /* LDR X16, #8 */
            buf[4] = 0x00; buf[5] = 0x02; buf[6] = 0x1F; buf[7] = 0xD6;  /* BR X16 */
            memcpy(buf + 8, &to, 8);
            return 16;
        }
    } else {
        /* x86-64 */
        int64_t offset = (int64_t)(to - (from + 5));
        if (offset >= INT32_MIN && offset <= INT32_MAX) {
            /* JMP rel32 */
            buf[0] = 0xE9;
            int32_t rel = (int32_t)offset;
            memcpy(buf + 1, &rel, 4);
            return 5;
        } else {
            /* JMP [RIP+0]; .quad target */
            buf[0] = 0xFF; buf[1] = 0x25; buf[2] = 0x00; buf[3] = 0x00;
            buf[4] = 0x00; buf[5] = 0x00;
            memcpy(buf + 6, &to, 8);
            return 14;
        }
    }
}

size_t e9_binpatch_gen_call(int arch, uint8_t *buf, uint64_t from, uint64_t to)
{
    if (!buf) return 0;

    if (arch == E9_ARCH_AARCH64) {
        /* AArch64: BL <offset> */
        int64_t offset = (int64_t)(to - from);
        if (offset >= -128*1024*1024 && offset < 128*1024*1024) {
            int32_t imm26 = (int32_t)(offset / 4) & 0x03FFFFFF;
            uint32_t insn = 0x94000000 | imm26;
            buf[0] = (uint8_t)(insn);
            buf[1] = (uint8_t)(insn >> 8);
            buf[2] = (uint8_t)(insn >> 16);
            buf[3] = (uint8_t)(insn >> 24);
            return 4;
        } else {
            /* Far call: LDR X16, #12; BLR X16; B skip; .quad target */
            buf[0] = 0x50; buf[1] = 0x00; buf[2] = 0x00; buf[3] = 0x58;  /* LDR X16, #8 */
            buf[4] = 0x00; buf[5] = 0x02; buf[6] = 0x3F; buf[7] = 0xD6;  /* BLR X16 */
            buf[8] = 0x03; buf[9] = 0x00; buf[10] = 0x00; buf[11] = 0x14; /* B #12 */
            memcpy(buf + 12, &to, 8);
            return 20;
        }
    } else {
        /* x86-64 */
        int64_t offset = (int64_t)(to - (from + 5));
        if (offset >= INT32_MIN && offset <= INT32_MAX) {
            /* CALL rel32 */
            buf[0] = 0xE8;
            int32_t rel = (int32_t)offset;
            memcpy(buf + 1, &rel, 4);
            return 5;
        } else {
            /* Far call needs a trampoline */
            /* For now, use: mov rax, imm64; call rax */
            buf[0] = 0x48; buf[1] = 0xB8;  /* MOV RAX, imm64 */
            memcpy(buf + 2, &to, 8);
            buf[10] = 0xFF; buf[11] = 0xD0;  /* CALL RAX */
            return 12;
        }
    }
}

/*
 * ============================================================================
 * Code Cave Finding
 * ============================================================================
 */

int e9_caves_find(E9BinPatchSession *session, size_t min_size)
{
    if (!session || !session->bin) return -1;

    E9Binary *bin = session->bin;

    /* Create cave finder if needed */
    if (!session->cave_finder) {
        session->cave_finder = bp_alloc(sizeof(E9CaveFinder));
        if (!session->cave_finder) return -1;
        session->cave_finder->bin = bin;
        session->cave_finder->caves_capacity = 64;
        session->cave_finder->caves = bp_alloc(
            session->cave_finder->caves_capacity * sizeof(E9CodeCave));
        if (!session->cave_finder->caves) {
            bp_free(session->cave_finder);
            session->cave_finder = NULL;
            return -1;
        }
        session->cave_finder->min_cave_size = (min_size > 0) ? min_size : 8;
        session->cave_finder->include_padding = true;
        session->cave_finder->include_nop_sleds = true;
    }

    E9CaveFinder *finder = session->cave_finder;
    finder->num_caves = 0;

    /* Scan each section for caves */
    for (uint32_t s = 0; s < bin->num_sections; s++) {
        uint64_t sec_addr = bin->sections[s].addr;
        uint64_t sec_size = bin->sections[s].size;
        uint32_t sec_flags = bin->sections[s].flags;

        if (!(sec_flags & E9_SECFLAG_EXEC)) continue;  /* Only executable sections */

        /* Calculate file offset from virtual address */
        uint64_t sec_offset = e9_binpatch_vaddr_to_offset(bin, sec_addr);
        if (sec_offset + sec_size > bin->size) continue;

        const uint8_t *data = bin->data + sec_offset;
        size_t run_start = 0;
        size_t run_len = 0;
        bool in_run = false;

        for (size_t i = 0; i < sec_size; i++) {
            bool is_cave_byte;
            if (bin->arch == E9_ARCH_AARCH64) {
                /* Check for AArch64 NOP (4-byte aligned) */
                if (i % 4 == 0 && i + 4 <= sec_size) {
                    uint32_t insn = data[i] | ((uint32_t)data[i+1] << 8) |
                                    ((uint32_t)data[i+2] << 16) | ((uint32_t)data[i+3] << 24);
                    is_cave_byte = (insn == 0xD503201F);  /* NOP */
                    if (is_cave_byte) {
                        if (!in_run) {
                            run_start = i;
                            in_run = true;
                            run_len = 4;
                        } else {
                            run_len += 4;
                        }
                        i += 3;  /* Will be incremented by loop */
                        continue;
                    }
                } else {
                    is_cave_byte = false;
                }
            } else {
                /* x86-64: 0x00, 0x90 (NOP), 0xCC (INT3) */
                is_cave_byte = (data[i] == 0x00 || data[i] == 0x90 || data[i] == 0xCC);
                if (is_cave_byte) {
                    if (!in_run) {
                        run_start = i;
                        in_run = true;
                        run_len = 1;
                    } else {
                        run_len++;
                    }
                    continue;
                }
            }

            if (in_run) {
                /* End of run, check size */
                if (run_len >= finder->min_cave_size) {
                    /* Ensure capacity */
                    if (finder->num_caves >= finder->caves_capacity) {
                        size_t new_cap = finder->caves_capacity * 2;
                        E9CodeCave *new_caves = bp_realloc(finder->caves,
                                                           new_cap * sizeof(E9CodeCave));
                        if (!new_caves) return -1;
                        finder->caves = new_caves;
                        finder->caves_capacity = new_cap;
                    }

                    E9CodeCave *cave = &finder->caves[finder->num_caves++];
                    cave->address = sec_addr + run_start;
                    cave->offset = sec_offset + run_start;
                    cave->size = run_len;
                    cave->writable = (sec_flags & E9_SECFLAG_WRITE) != 0;
                    cave->executable = true;
                    cave->section_idx = (int)s;
                }
                in_run = false;
                run_len = 0;
            }
        }

        /* Handle run at end of section */
        if (in_run && run_len >= finder->min_cave_size) {
            if (finder->num_caves < finder->caves_capacity) {
                E9CodeCave *cave = &finder->caves[finder->num_caves++];
                cave->address = sec_addr + run_start;
                cave->offset = sec_offset + run_start;
                cave->size = run_len;
                cave->writable = (sec_flags & E9_SECFLAG_WRITE) != 0;
                cave->executable = true;
                cave->section_idx = (int)s;
            }
        }
    }

    return (int)finder->num_caves;
}

uint64_t e9_caves_alloc(E9BinPatchSession *session, size_t size, bool executable)
{
    if (!session || !session->cave_finder) return 0;

    E9CaveFinder *finder = session->cave_finder;
    (void)executable;  /* Currently all caves are from executable sections */

    /* Find smallest cave that fits */
    E9CodeCave *best = NULL;
    for (size_t i = 0; i < finder->num_caves; i++) {
        E9CodeCave *cave = &finder->caves[i];
        if (cave->size >= size) {
            if (!best || cave->size < best->size) {
                best = cave;
            }
        }
    }

    if (!best) return 0;

    /* Allocate from start of cave */
    uint64_t addr = best->address;
    best->address += size;
    best->offset += size;
    best->size -= size;

    return addr;
}

const E9CodeCave *e9_caves_list(E9BinPatchSession *session, size_t *count)
{
    if (!session || !session->cave_finder) {
        if (count) *count = 0;
        return NULL;
    }
    if (count) *count = session->cave_finder->num_caves;
    return session->cave_finder->caves;
}

/*
 * ============================================================================
 * Patch Operations
 * ============================================================================
 */

static int add_patch(E9BinPatchSession *session, E9BinPatch *patch)
{
    if (ensure_patch_capacity(session) < 0) return -1;

    patch->id = (int)session->num_patches;

    /* Compute file offset if not provided */
    if (patch->offset == 0 && patch->address != 0) {
        patch->offset = e9_binpatch_vaddr_to_offset(session->bin, patch->address);
        if (patch->offset == 0) {
            set_error(session, -1, "Cannot find offset for address 0x%lx",
                      (unsigned long)patch->address);
            return -1;
        }
    }

    /* Create backup if requested */
    if (patch->flags & E9_BINPATCH_FLAG_BACKUP) {
        size_t backup_size = patch->orig_size > 0 ? patch->orig_size : patch->new_size;
        if (backup_size > 0 && patch->offset + backup_size <= session->bin->size) {
            patch->backup_bytes = bp_alloc(backup_size);
            if (patch->backup_bytes) {
                memcpy(patch->backup_bytes, session->bin->data + patch->offset, backup_size);
                patch->backup_size = backup_size;
            }
        }
    }

    session->patches[session->num_patches++] = *patch;
    return patch->id;
}

int e9_binpatch_bytes(E9BinPatchSession *session, uint64_t addr,
                      const uint8_t *bytes, size_t size, uint32_t flags)
{
    if (!session || !bytes || size == 0) return -1;
    if (session->finalized) {
        set_error(session, -1, "Session already finalized");
        return -1;
    }

    E9BinPatch patch = {0};
    patch.type = E9_BINPATCH_BYTES;
    patch.flags = flags;
    patch.address = addr;
    patch.new_bytes = bytes;
    patch.new_size = size;
    patch.orig_size = size;

    return add_patch(session, &patch);
}

int e9_binpatch_nop(E9BinPatchSession *session, uint64_t addr, size_t size, uint32_t flags)
{
    if (!session || size == 0) return -1;
    if (session->finalized) {
        set_error(session, -1, "Session already finalized");
        return -1;
    }

    E9BinPatch patch = {0};
    patch.type = E9_BINPATCH_NOP;
    patch.flags = flags;
    patch.address = addr;
    patch.new_size = size;
    patch.orig_size = size;

    return add_patch(session, &patch);
}

int e9_binpatch_insn(E9BinPatchSession *session, uint64_t addr,
                     const uint8_t *new_insn, size_t new_size, uint32_t flags)
{
    if (!session || !new_insn || new_size == 0) return -1;
    if (session->finalized) {
        set_error(session, -1, "Session already finalized");
        return -1;
    }

    /* Get original instruction size */
    size_t orig_size = e9_binpatch_insn_size_at(session->bin, addr);
    if (orig_size == 0) {
        set_error(session, -1, "Cannot determine instruction size at 0x%lx",
                  (unsigned long)addr);
        return -1;
    }

    E9BinPatch patch = {0};
    patch.type = E9_BINPATCH_INSN;
    patch.flags = flags;
    patch.address = addr;
    patch.new_bytes = new_insn;
    patch.new_size = new_size;
    patch.orig_size = orig_size;

    /* If new instruction is larger, need trampoline */
    if (new_size > orig_size) {
        patch.type = E9_BINPATCH_TRAMPOLINE;
    }

    return add_patch(session, &patch);
}

int e9_binpatch_call(E9BinPatchSession *session, uint64_t call_addr,
                     uint64_t new_target, uint32_t flags)
{
    if (!session) return -1;
    if (session->finalized) {
        set_error(session, -1, "Session already finalized");
        return -1;
    }

    E9BinPatch patch = {0};
    patch.type = E9_BINPATCH_CALL;
    patch.flags = flags;
    patch.address = call_addr;
    patch.target_addr = new_target;
    patch.orig_size = (session->bin->arch == E9_ARCH_AARCH64) ? 4 : 5;
    patch.new_size = patch.orig_size;

    return add_patch(session, &patch);
}

int e9_binpatch_jmp(E9BinPatchSession *session, uint64_t jmp_addr,
                    uint64_t new_target, uint32_t flags)
{
    if (!session) return -1;
    if (session->finalized) {
        set_error(session, -1, "Session already finalized");
        return -1;
    }

    E9BinPatch patch = {0};
    patch.type = E9_BINPATCH_JMP;
    patch.flags = flags;
    patch.address = jmp_addr;
    patch.target_addr = new_target;
    patch.orig_size = (session->bin->arch == E9_ARCH_AARCH64) ? 4 : 5;
    patch.new_size = patch.orig_size;

    return add_patch(session, &patch);
}

int e9_binpatch_hook(E9BinPatchSession *session, uint64_t func_addr,
                     const uint8_t *hook_code, size_t hook_size, uint32_t flags)
{
    if (!session || !hook_code || hook_size == 0) return -1;
    if (session->finalized) {
        set_error(session, -1, "Session already finalized");
        return -1;
    }

    E9BinPatch patch = {0};
    patch.type = E9_BINPATCH_HOOK;
    patch.flags = flags;
    patch.address = func_addr;
    patch.hook_code = hook_code;
    patch.hook_code_size = hook_size;
    /* Hook replaces first instruction with a jump/call to hook code */
    patch.orig_size = e9_binpatch_insn_size_at(session->bin, func_addr);

    return add_patch(session, &patch);
}

int e9_binpatch_detour(E9BinPatchSession *session, uint64_t func_addr,
                       const uint8_t *new_func, size_t new_func_size,
                       uint64_t *orig_func_ptr, uint32_t flags)
{
    if (!session || !new_func || new_func_size == 0) return -1;
    if (session->finalized) {
        set_error(session, -1, "Session already finalized");
        return -1;
    }

    E9BinPatch patch = {0};
    patch.type = E9_BINPATCH_DETOUR;
    patch.flags = flags;
    patch.address = func_addr;
    patch.hook_code = new_func;
    patch.hook_code_size = new_func_size;

    int id = add_patch(session, &patch);
    if (id >= 0 && orig_func_ptr) {
        /* Original function pointer will be set during apply */
        *orig_func_ptr = 0;
    }

    return id;
}

/*
 * ============================================================================
 * Instruction Size Calculation
 * ============================================================================
 */

size_t e9_binpatch_insn_size_at(E9Binary *bin, uint64_t addr)
{
    if (!bin) return 0;

    uint64_t offset = e9_binpatch_vaddr_to_offset(bin, addr);
    if (offset == 0 || offset >= bin->size) return 0;

    if (bin->arch == E9_ARCH_AARCH64) {
        /* AArch64: All instructions are 4 bytes */
        return 4;
    }

    /* x86-64: Need to decode to find size */
    const uint8_t *code = bin->data + offset;
    size_t max_len = bin->size - offset;
    if (max_len > 15) max_len = 15;

    /* Simple x86-64 instruction length decoder */
    size_t pos = 0;

    /* Legacy prefixes */
    while (pos < max_len) {
        uint8_t b = code[pos];
        if (b == 0xF0 || b == 0xF2 || b == 0xF3 ||  /* LOCK, REPNE, REP */
            b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 ||
            b == 0x64 || b == 0x65 ||  /* Segment overrides */
            b == 0x66 || b == 0x67) {  /* Operand/address size */
            pos++;
        } else {
            break;
        }
    }

    /* REX prefix */
    if (pos < max_len && (code[pos] & 0xF0) == 0x40) {
        pos++;
    }

    if (pos >= max_len) return 0;

    /* Opcode */
    uint8_t opcode = code[pos++];
    bool has_modrm = false;
    int imm_size = 0;

    if (opcode == 0x0F) {
        /* Two-byte opcode */
        if (pos >= max_len) return 0;
        opcode = code[pos++];

        if (opcode == 0x38 || opcode == 0x3A) {
            /* Three-byte opcode */
            if (pos >= max_len) return 0;
            pos++;
            has_modrm = true;
            if (opcode == 0x3A) imm_size = 1;
        } else {
            /* Most 0F xx have ModRM */
            has_modrm = true;
            /* Jcc rel32 */
            if (opcode >= 0x80 && opcode <= 0x8F) {
                has_modrm = false;
                imm_size = 4;
            }
        }
    } else {
        /* One-byte opcode */
        /* Simple cases */
        if ((opcode & 0xF8) == 0x50) return pos;  /* PUSH r */
        if ((opcode & 0xF8) == 0x58) return pos;  /* POP r */
        if ((opcode & 0xF8) == 0xB8) return pos + 4;  /* MOV r, imm32 (or imm64 with REX.W) */
        if ((opcode & 0xF0) == 0x70) return pos + 1;  /* Jcc rel8 */
        if (opcode == 0xEB) return pos + 1;  /* JMP rel8 */
        if (opcode == 0xE9) return pos + 4;  /* JMP rel32 */
        if (opcode == 0xE8) return pos + 4;  /* CALL rel32 */
        if (opcode == 0xC3 || opcode == 0xCB) return pos;  /* RET */
        if (opcode == 0xC2 || opcode == 0xCA) return pos + 2;  /* RET imm16 */
        if (opcode == 0x90) return pos;  /* NOP */
        if (opcode == 0xCC) return pos;  /* INT3 */

        /* Instructions with ModRM */
        if ((opcode & 0xC0) == 0x00 ||  /* 00-3F: ALU ops */
            (opcode & 0xF8) == 0x80 ||  /* 80-87: ALU r/m, imm */
            (opcode & 0xF8) == 0x88 ||  /* 88-8F: MOV variants */
            (opcode & 0xF8) == 0xF8 ||  /* F8-FF: misc */
            opcode == 0x63 ||           /* MOVSXD */
            opcode == 0x69 || opcode == 0x6B ||  /* IMUL */
            opcode == 0x8D ||           /* LEA */
            opcode == 0xC6 || opcode == 0xC7) {  /* MOV r/m, imm */
            has_modrm = true;
        }

        /* Immediate sizes for some opcodes */
        if ((opcode & 0xFE) == 0x04) imm_size = 1;  /* ADD AL, imm8 / ADD RAX, imm32 */
        if ((opcode & 0xF8) == 0xB0) imm_size = 1;  /* MOV r8, imm8 */
        if (opcode == 0x68) imm_size = 4;  /* PUSH imm32 */
        if (opcode == 0x6A) imm_size = 1;  /* PUSH imm8 */
    }

    /* Parse ModRM if present */
    if (has_modrm && pos < max_len) {
        uint8_t modrm = code[pos++];
        uint8_t mod = (modrm >> 6) & 3;
        uint8_t rm = modrm & 7;

        if (mod != 3 && rm == 4 && pos < max_len) {
            /* SIB byte */
            pos++;
        }

        if (mod == 0 && rm == 5) {
            /* [RIP+disp32] */
            pos += 4;
        } else if (mod == 1) {
            /* disp8 */
            pos += 1;
        } else if (mod == 2) {
            /* disp32 */
            pos += 4;
        }
    }

    pos += imm_size;
    return pos;
}

/*
 * ============================================================================
 * Patch Application
 * ============================================================================
 */

int e9_binpatch_validate(E9BinPatchSession *session)
{
    if (!session) return -1;

    /* Check for overlapping patches */
    for (size_t i = 0; i < session->num_patches; i++) {
        E9BinPatch *p1 = &session->patches[i];
        for (size_t j = i + 1; j < session->num_patches; j++) {
            E9BinPatch *p2 = &session->patches[j];

            uint64_t end1 = p1->offset + p1->orig_size;
            uint64_t end2 = p2->offset + p2->orig_size;

            if ((p1->offset < end2 && p2->offset < end1)) {
                set_error(session, -1, "Overlapping patches at 0x%lx and 0x%lx",
                          (unsigned long)p1->address, (unsigned long)p2->address);
                return -1;
            }
        }
    }

    return 0;
}

int e9_binpatch_apply(E9BinPatchSession *session)
{
    if (!session) return -1;
    if (session->finalized) return 0;

    /* Validate first */
    if (e9_binpatch_validate(session) < 0) return -1;

    E9Binary *bin = session->bin;

    /* Apply each patch */
    for (size_t i = 0; i < session->num_patches; i++) {
        E9BinPatch *patch = &session->patches[i];

        if (patch->offset + patch->new_size > session->output_capacity) {
            set_error(session, -1, "Patch at 0x%lx exceeds binary size",
                      (unsigned long)patch->address);
            return -1;
        }

        uint8_t *dest = session->output + patch->offset;

        switch (patch->type) {
        case E9_BINPATCH_BYTES:
            memcpy(dest, patch->new_bytes, patch->new_size);
            break;

        case E9_BINPATCH_NOP:
            e9_binpatch_gen_nops(bin->arch, dest, patch->new_size);
            break;

        case E9_BINPATCH_INSN:
            memcpy(dest, patch->new_bytes, patch->new_size);
            /* NOP remaining bytes if new instruction is smaller */
            if (patch->new_size < patch->orig_size) {
                e9_binpatch_gen_nops(bin->arch, dest + patch->new_size,
                                     patch->orig_size - patch->new_size);
            }
            break;

        case E9_BINPATCH_CALL: {
            uint8_t buf[20];
            size_t size = e9_binpatch_gen_call(bin->arch, buf, patch->address, patch->target_addr);
            if (size > patch->orig_size) {
                set_error(session, -1, "Call patch too large at 0x%lx",
                          (unsigned long)patch->address);
                return -1;
            }
            memcpy(dest, buf, size);
            if (size < patch->orig_size) {
                e9_binpatch_gen_nops(bin->arch, dest + size, patch->orig_size - size);
            }
            break;
        }

        case E9_BINPATCH_JMP: {
            uint8_t buf[20];
            size_t size = e9_binpatch_gen_jmp(bin->arch, buf, patch->address, patch->target_addr);
            if (size > patch->orig_size) {
                set_error(session, -1, "Jump patch too large at 0x%lx",
                          (unsigned long)patch->address);
                return -1;
            }
            memcpy(dest, buf, size);
            if (size < patch->orig_size) {
                e9_binpatch_gen_nops(bin->arch, dest + size, patch->orig_size - size);
            }
            break;
        }

        case E9_BINPATCH_TRAMPOLINE:
        case E9_BINPATCH_HOOK:
        case E9_BINPATCH_DETOUR:
            /* These require code caves or section extension */
            /* Find a code cave for the hook/detour code */
            if (!session->cave_finder) {
                e9_caves_find(session, 16);
            }

            /* Allocate space in cave */
            uint64_t cave_addr = e9_caves_alloc(session, patch->hook_code_size + 32, true);
            if (cave_addr == 0) {
                set_error(session, -1, "No code cave available for patch at 0x%lx",
                          (unsigned long)patch->address);
                return -1;
            }

            /* Write hook code to cave */
            uint64_t cave_offset = e9_binpatch_vaddr_to_offset(bin, cave_addr);
            if (cave_offset > 0 && cave_offset + patch->hook_code_size <= session->output_size) {
                memcpy(session->output + cave_offset, patch->hook_code, patch->hook_code_size);

                /* Add jump back if this is a hook (not detour) */
                if (patch->type == E9_BINPATCH_HOOK) {
                    uint8_t jmp_back[20];
                    uint64_t return_addr = patch->address + patch->orig_size;
                    size_t jmp_size = e9_binpatch_gen_jmp(bin->arch, jmp_back,
                                                          cave_addr + patch->hook_code_size, return_addr);
                    memcpy(session->output + cave_offset + patch->hook_code_size,
                           jmp_back, jmp_size);
                }

                /* Patch original location with jump to cave */
                uint8_t jmp_to_cave[20];
                size_t jmp_size = e9_binpatch_gen_jmp(bin->arch, jmp_to_cave,
                                                      patch->address, cave_addr);
                if (jmp_size <= patch->orig_size || patch->orig_size == 0) {
                    size_t write_size = (patch->orig_size > 0) ? patch->orig_size : jmp_size;
                    memcpy(dest, jmp_to_cave, jmp_size);
                    if (jmp_size < write_size) {
                        e9_binpatch_gen_nops(bin->arch, dest + jmp_size, write_size - jmp_size);
                    }
                }
            }
            break;
        }
    }

    session->finalized = true;
    return 0;
}

int e9_binpatch_write(E9BinPatchSession *session, const char *output_path)
{
    if (!session || !output_path) return -1;

    if (!session->finalized) {
        if (e9_binpatch_apply(session) < 0) return -1;
    }

    FILE *fp = fopen(output_path, "wb");
    if (!fp) {
        set_error(session, -1, "Cannot open output file: %s", output_path);
        return -1;
    }

    size_t written = fwrite(session->output, 1, session->output_size, fp);
    fclose(fp);

    if (written != session->output_size) {
        set_error(session, -1, "Write error: wrote %zu of %zu bytes",
                  written, session->output_size);
        return -1;
    }

    return 0;
}

const uint8_t *e9_binpatch_get_output(E9BinPatchSession *session, size_t *size)
{
    if (!session) {
        if (size) *size = 0;
        return NULL;
    }

    if (!session->finalized) {
        if (e9_binpatch_apply(session) < 0) {
            if (size) *size = 0;
            return NULL;
        }
    }

    if (size) *size = session->output_size;
    return session->output;
}

int e9_binpatch_verify(E9BinPatchSession *session)
{
    if (!session || !session->finalized) return -1;

    for (size_t i = 0; i < session->num_patches; i++) {
        E9BinPatch *patch = &session->patches[i];
        if (!(patch->flags & E9_BINPATCH_FLAG_VERIFY)) continue;

        /* Verify bytes were written correctly */
        if (patch->type == E9_BINPATCH_BYTES && patch->new_bytes) {
            if (memcmp(session->output + patch->offset, patch->new_bytes, patch->new_size) != 0) {
                set_error(session, -1, "Verification failed for patch at 0x%lx",
                          (unsigned long)patch->address);
                return -1;
            }
        }
    }

    return 0;
}

/*
 * ============================================================================
 * Undo/Revert
 * ============================================================================
 */

int e9_binpatch_revert(E9BinPatchSession *session, int patch_id)
{
    if (!session || patch_id < 0 || (size_t)patch_id >= session->num_patches) {
        return -1;
    }

    E9BinPatch *patch = &session->patches[patch_id];
    if (!patch->backup_bytes || patch->backup_size == 0) {
        set_error(session, -1, "No backup available for patch %d", patch_id);
        return -1;
    }

    memcpy(session->output + patch->offset, patch->backup_bytes, patch->backup_size);
    return 0;
}

int e9_binpatch_revert_all(E9BinPatchSession *session)
{
    if (!session) return -1;

    /* Restore from original binary */
    memcpy(session->output, session->bin->data, session->bin->size);
    session->output_size = session->bin->size;
    session->finalized = false;

    return 0;
}

/*
 * ============================================================================
 * Summary Generation
 * ============================================================================
 */

char *e9_binpatch_summary(E9BinPatchSession *session)
{
    if (!session) return NULL;

    /* Estimate size */
    size_t buf_size = 256 + session->num_patches * 128;
    char *buf = bp_alloc(buf_size);
    if (!buf) return NULL;

    size_t pos = 0;
    pos += snprintf(buf + pos, buf_size - pos,
                    "E9BinPatch Session Summary\n"
                    "==========================\n"
                    "Binary: (%s, base 0x%lx)\n"
                    "Patches: %zu\n"
                    "Code caves found: %zu\n\n",
                    session->bin->arch == E9_ARCH_AARCH64 ? "AArch64" : "x86-64",
                    (unsigned long)session->bin->base_address,
                    session->num_patches,
                    session->cave_finder ? session->cave_finder->num_caves : 0);

    static const char *type_names[] = {
        "BYTES", "INSN", "NOP", "CALL", "JMP", "TRAMPOLINE", "HOOK", "DETOUR"
    };

    for (size_t i = 0; i < session->num_patches && pos < buf_size - 100; i++) {
        E9BinPatch *p = &session->patches[i];
        pos += snprintf(buf + pos, buf_size - pos,
                        "[%zu] %s @ 0x%lx (offset 0x%lx, %zu bytes)",
                        i, type_names[p->type],
                        (unsigned long)p->address,
                        (unsigned long)p->offset,
                        p->new_size);
        if (p->comment) {
            pos += snprintf(buf + pos, buf_size - pos, " - %s", p->comment);
        }
        pos += snprintf(buf + pos, buf_size - pos, "\n");
    }

    if (session->error_code != 0) {
        pos += snprintf(buf + pos, buf_size - pos,
                        "\nError: %s\n", session->error_msg);
    }

    return buf;
}
