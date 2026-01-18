/*
 * e9studio_analysis.c
 * Integration layer between E9Analysis engine and E9Studio
 *
 * Provides real-time binary analysis for the E9Studio TUI,
 * including live disassembly, decompilation, and patch generation.
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

#include "e9analysis.h"
#include "../wasm/e9wasm_host.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifdef __COSMOPOLITAN__
#include "cosmopolitan.h"
#endif

/*
 * Studio Analysis Context
 */
typedef struct {
    E9Binary *binary;           /* Current binary under analysis */
    E9Function *current_func;   /* Currently selected function */
    E9BasicBlock *current_block;/* Currently selected block */

    /* View state */
    uint64_t view_addr;         /* Current address in view */
    int view_mode;              /* 0=disasm, 1=decompile, 2=hex */

    /* Source editing context */
    char *source_file;          /* Associated source file path */
    uint8_t *compiled_obj;      /* Compiled object file */
    size_t compiled_size;

    /* Patch tracking */
    E9PatchSet *pending_patches;/* Patches to apply */
    bool patches_modified;

    /* Statistics */
    uint32_t total_functions;
    uint32_t analyzed_functions;
    uint32_t total_symbols;
} E9StudioContext;

static E9StudioContext *g_studio = NULL;

/*
 * ============================================================================
 * Studio Context Management
 * ============================================================================
 */

int e9studio_analysis_init(void)
{
    if (g_studio) return 0;  /* Already initialized */

    g_studio = (E9StudioContext *)calloc(1, sizeof(E9StudioContext));
    if (!g_studio) {
        fprintf(stderr, "e9studio: Failed to allocate analysis context\n");
        return -1;
    }

    return 0;
}

void e9studio_analysis_shutdown(void)
{
    if (!g_studio) return;

    if (g_studio->binary) {
        e9_binary_free(g_studio->binary);
    }
    if (g_studio->source_file) {
        free(g_studio->source_file);
    }
    if (g_studio->compiled_obj) {
        free(g_studio->compiled_obj);
    }
    if (g_studio->pending_patches) {
        e9_patchset_free(g_studio->pending_patches);
    }

    free(g_studio);
    g_studio = NULL;
}

/*
 * ============================================================================
 * Binary Loading and Analysis
 * ============================================================================
 */

int e9studio_load_binary(const char *path)
{
    if (!g_studio || !path) return -1;

    /* Free existing binary */
    if (g_studio->binary) {
        e9_binary_free(g_studio->binary);
        g_studio->binary = NULL;
    }

    /* Read file */
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, "e9studio: Cannot open %s\n", path);
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    size_t size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    uint8_t *data = (uint8_t *)malloc(size);
    if (!data) {
        fclose(fp);
        return -1;
    }

    if (fread(data, 1, size, fp) != size) {
        free(data);
        fclose(fp);
        return -1;
    }
    fclose(fp);

    /* Create binary context */
    g_studio->binary = e9_binary_create(data, size);
    if (!g_studio->binary) {
        free(data);
        return -1;
    }

    /* Run full analysis */
    printf("Analyzing binary (%zu bytes)...\n", size);
    if (e9_binary_analyze(g_studio->binary) != 0) {
        fprintf(stderr, "e9studio: Analysis failed\n");
        return -1;
    }

    /* Update statistics */
    g_studio->total_functions = g_studio->binary->num_functions;
    g_studio->total_symbols = g_studio->binary->num_symbols;

    /* Set initial view */
    g_studio->view_addr = g_studio->binary->entry_point;
    g_studio->current_func = e9_function_at(g_studio->binary, g_studio->view_addr);

    printf("Analysis complete: %u functions, %u symbols\n",
           g_studio->total_functions, g_studio->total_symbols);

    return 0;
}

int e9studio_load_from_zipos(const char *zip_path)
{
    if (!g_studio || !zip_path) return -1;

    /* Use wasm host to mmap from ZipOS */
    size_t size;
    void *data = e9wasm_mmap_binary(zip_path, &size, false);
    if (!data) {
        fprintf(stderr, "e9studio: Cannot load from ZipOS: %s\n", zip_path);
        return -1;
    }

    /* Create binary context */
    g_studio->binary = e9_binary_create((uint8_t *)data, size);
    if (!g_studio->binary) {
        e9wasm_munmap_binary(data, size);
        return -1;
    }

    /* Analyze */
    if (e9_binary_analyze(g_studio->binary) != 0) {
        e9wasm_munmap_binary(data, size);
        return -1;
    }

    g_studio->total_functions = g_studio->binary->num_functions;
    g_studio->total_symbols = g_studio->binary->num_symbols;
    g_studio->view_addr = g_studio->binary->entry_point;

    return 0;
}

/*
 * ============================================================================
 * Navigation
 * ============================================================================
 */

int e9studio_goto_address(uint64_t addr)
{
    if (!g_studio || !g_studio->binary) return -1;

    g_studio->view_addr = addr;
    g_studio->current_func = e9_function_at(g_studio->binary, addr);

    if (g_studio->current_func && g_studio->current_func->cfg) {
        /* Find containing block */
        E9CFG *cfg = g_studio->current_func->cfg;
        for (uint32_t i = 0; i < cfg->num_blocks; i++) {
            if (addr >= cfg->blocks[i]->start_addr &&
                addr < cfg->blocks[i]->end_addr) {
                g_studio->current_block = cfg->blocks[i];
                break;
            }
        }
    }

    return 0;
}

int e9studio_goto_function(const char *name)
{
    if (!g_studio || !g_studio->binary || !name) return -1;

    E9Function *func = e9_function_by_name(g_studio->binary, name);
    if (!func) {
        /* Try symbol lookup */
        E9Symbol *sym = e9_symbol_by_name(g_studio->binary, name);
        if (sym) {
            func = e9_function_at(g_studio->binary, sym->address);
        }
    }

    if (func) {
        g_studio->current_func = func;
        g_studio->view_addr = func->address;
        if (func->cfg) {
            g_studio->current_block = func->cfg->entry;
        }
        return 0;
    }

    return -1;
}

int e9studio_next_function(void)
{
    if (!g_studio || !g_studio->binary) return -1;

    if (g_studio->current_func && g_studio->current_func->next) {
        g_studio->current_func = g_studio->current_func->next;
        g_studio->view_addr = g_studio->current_func->address;
        if (g_studio->current_func->cfg) {
            g_studio->current_block = g_studio->current_func->cfg->entry;
        }
        return 0;
    }

    return -1;
}

int e9studio_prev_function(void)
{
    if (!g_studio || !g_studio->binary) return -1;

    /* Find previous function (linear search through list) */
    E9Function *prev = NULL;
    E9Function *func = g_studio->binary->functions;

    while (func) {
        if (func == g_studio->current_func && prev) {
            g_studio->current_func = prev;
            g_studio->view_addr = prev->address;
            if (prev->cfg) {
                g_studio->current_block = prev->cfg->entry;
            }
            return 0;
        }
        prev = func;
        func = func->next;
    }

    return -1;
}

/*
 * ============================================================================
 * View Generation for TUI
 * ============================================================================
 */

const char *e9studio_get_disassembly(uint64_t addr, int num_lines, char *buf, size_t buf_size)
{
    if (!g_studio || !g_studio->binary || !buf || buf_size == 0) return "";

    size_t pos = 0;
    uint64_t current = addr;
    char line_buf[256];

    for (int i = 0; i < num_lines && pos < buf_size - 256; i++) {
        E9Instruction *insn = e9_disasm_one(g_studio->binary, current);
        if (!insn) break;

        /* Check for symbol at this address */
        E9Symbol *sym = e9_symbol_at(g_studio->binary, current);
        if (sym && sym->address == current) {
            pos += snprintf(buf + pos, buf_size - pos, "\n<%s>:\n",
                           sym->name ? sym->name : "unknown");
        }

        /* Format instruction */
        e9_disasm_str(g_studio->binary, insn, line_buf, sizeof(line_buf));
        pos += snprintf(buf + pos, buf_size - pos, "%s\n", line_buf);

        current += insn->size;
        free(insn);
    }

    return buf;
}

const char *e9studio_get_decompiled(const char *func_name, char *buf, size_t buf_size)
{
    if (!g_studio || !g_studio->binary || !buf || buf_size == 0) return "";

    E9Function *func = NULL;

    if (func_name) {
        func = e9_function_by_name(g_studio->binary, func_name);
    } else {
        func = g_studio->current_func;
    }

    if (!func) {
        snprintf(buf, buf_size, "// Function not found\n");
        return buf;
    }

    /* Build CFG if needed */
    if (!func->cfg) {
        func->cfg = e9_cfg_build(g_studio->binary, func);
    }

    /* Decompile if needed */
    if (!func->decompiled_c) {
        e9_decompile_function(g_studio->binary, func);
    }

    if (func->decompiled_c) {
        strncpy(buf, func->decompiled_c, buf_size - 1);
        buf[buf_size - 1] = '\0';
    } else {
        snprintf(buf, buf_size, "// Decompilation failed\n");
    }

    return buf;
}

const char *e9studio_get_hex_view(uint64_t addr, int num_rows, char *buf, size_t buf_size)
{
    if (!g_studio || !g_studio->binary || !buf || buf_size == 0) return "";

    /* Convert address to offset */
    uint64_t offset;
    if (g_studio->binary->base_address && addr >= g_studio->binary->base_address) {
        offset = addr - g_studio->binary->base_address;
    } else {
        offset = addr;
    }

    size_t pos = 0;
    const uint8_t *data = g_studio->binary->data;
    size_t size = g_studio->binary->size;

    for (int row = 0; row < num_rows && pos < buf_size - 128; row++) {
        uint64_t row_addr = addr + row * 16;
        uint64_t row_off = offset + row * 16;

        /* Address */
        pos += snprintf(buf + pos, buf_size - pos, "%016lx  ", row_addr);

        /* Hex bytes */
        for (int i = 0; i < 16; i++) {
            if (row_off + i < size) {
                pos += snprintf(buf + pos, buf_size - pos, "%02x ", data[row_off + i]);
            } else {
                pos += snprintf(buf + pos, buf_size - pos, "   ");
            }
            if (i == 7) {
                pos += snprintf(buf + pos, buf_size - pos, " ");
            }
        }

        /* ASCII */
        pos += snprintf(buf + pos, buf_size - pos, " |");
        for (int i = 0; i < 16; i++) {
            if (row_off + i < size) {
                uint8_t c = data[row_off + i];
                pos += snprintf(buf + pos, buf_size - pos, "%c",
                               (c >= 32 && c < 127) ? c : '.');
            }
        }
        pos += snprintf(buf + pos, buf_size - pos, "|\n");
    }

    return buf;
}

/*
 * ============================================================================
 * Function/Symbol List for TUI
 * ============================================================================
 */

typedef struct {
    const char *name;
    uint64_t address;
    uint32_t size;
    int type;  /* 0=function, 1=symbol */
} E9StudioListEntry;

int e9studio_get_function_list(E9StudioListEntry **entries, uint32_t *count)
{
    if (!g_studio || !g_studio->binary || !entries || !count) return -1;

    uint32_t num = g_studio->binary->num_functions;
    E9StudioListEntry *list = (E9StudioListEntry *)calloc(num, sizeof(E9StudioListEntry));
    if (!list) return -1;

    uint32_t i = 0;
    E9Function *func = g_studio->binary->functions;
    while (func && i < num) {
        list[i].name = func->name;
        list[i].address = func->address;
        list[i].size = func->size;
        list[i].type = 0;
        i++;
        func = func->next;
    }

    *entries = list;
    *count = i;
    return 0;
}

int e9studio_get_symbol_list(E9StudioListEntry **entries, uint32_t *count)
{
    if (!g_studio || !g_studio->binary || !entries || !count) return -1;

    uint32_t num = g_studio->binary->num_symbols;
    E9StudioListEntry *list = (E9StudioListEntry *)calloc(num, sizeof(E9StudioListEntry));
    if (!list) return -1;

    uint32_t i = 0;
    E9Symbol *sym = g_studio->binary->symbols;
    while (sym && i < num) {
        list[i].name = sym->name;
        list[i].address = sym->address;
        list[i].size = sym->size;
        list[i].type = 1;
        i++;
        sym = sym->next;
    }

    *entries = list;
    *count = i;
    return 0;
}

/*
 * ============================================================================
 * Source Code Integration
 * ============================================================================
 */

int e9studio_set_source_file(const char *path)
{
    if (!g_studio || !path) return -1;

    if (g_studio->source_file) {
        free(g_studio->source_file);
    }

    g_studio->source_file = strdup(path);
    return 0;
}

int e9studio_source_line_to_address(uint32_t line, uint64_t *addr)
{
    if (!g_studio || !g_studio->binary || !addr) return -1;

    if (!g_studio->source_file) {
        return -1;
    }

    return e9_dwarf_line_to_addr(g_studio->binary, g_studio->source_file, line, addr, NULL);
}

int e9studio_address_to_source_line(uint64_t addr, char *file, size_t file_size, uint32_t *line)
{
    if (!g_studio || !g_studio->binary) return -1;

    return e9_dwarf_addr_to_line(g_studio->binary, addr, file, file_size, line, NULL);
}

/*
 * ============================================================================
 * Live Patching
 * ============================================================================
 */

int e9studio_compile_source(const char *source_path, const char *output_path)
{
    if (!source_path) return -1;

    /* Determine compiler based on extension and architecture */
    const char *ext = strrchr(source_path, '.');
    const char *compiler = "cc";
    const char *flags = "-c -O2";

    if (g_studio && g_studio->binary) {
        if (g_studio->binary->arch == E9_ARCH_AARCH64) {
            compiler = "aarch64-linux-gnu-gcc";
        }
    }

    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "%s %s -o %s %s 2>&1",
             compiler, flags, output_path ? output_path : "/tmp/e9studio_obj.o",
             source_path);

    int ret = system(cmd);
    return ret == 0 ? 0 : -1;
}

int e9studio_on_source_change(const char *path)
{
    if (!g_studio || !g_studio->binary || !path) return -1;

    printf("Source file changed: %s\n", path);

    /* Step 1: Compile the changed source */
    const char *new_obj = "/tmp/e9studio_new.o";
    if (e9studio_compile_source(path, new_obj) != 0) {
        fprintf(stderr, "Compilation failed\n");
        return -1;
    }

    /* Step 2: Read compiled object */
    FILE *fp = fopen(new_obj, "rb");
    if (!fp) return -1;

    fseek(fp, 0, SEEK_END);
    size_t new_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    uint8_t *new_obj_data = (uint8_t *)malloc(new_size);
    if (!new_obj_data) {
        fclose(fp);
        return -1;
    }

    fread(new_obj_data, 1, new_size, fp);
    fclose(fp);

    /* Step 3: Diff against current binary */
    if (g_studio->pending_patches) {
        e9_patchset_free(g_studio->pending_patches);
    }

    g_studio->pending_patches = e9_diff_objects(
        g_studio->binary->data, g_studio->binary->size,
        new_obj_data, new_size);

    free(new_obj_data);

    if (!g_studio->pending_patches) {
        return -1;
    }

    if (g_studio->pending_patches->error) {
        fprintf(stderr, "Diff error: %s\n", g_studio->pending_patches->error);
        return -1;
    }

    printf("Generated %u patches\n", g_studio->pending_patches->num_patches);
    g_studio->patches_modified = true;

    return g_studio->pending_patches->num_patches;
}

int e9studio_apply_pending_patches(void)
{
    if (!g_studio || !g_studio->pending_patches || !g_studio->binary) return -1;

    E9PatchSet *ps = g_studio->pending_patches;
    int applied = 0;

    /* Get writable mapping of the binary */
    /* For live patching, we need the binary to be memory-mapped writable */

    for (uint32_t i = 0; i < ps->num_patches; i++) {
        E9Patch *patch = &ps->patches[i];

        /* Convert address to offset */
        uint64_t offset;
        if (g_studio->binary->base_address) {
            offset = patch->address - g_studio->binary->base_address;
        } else {
            offset = patch->address;
        }

        if (offset + patch->size > g_studio->binary->size) {
            fprintf(stderr, "Patch %u out of bounds\n", i);
            continue;
        }

        printf("Applying patch at 0x%lx (%u bytes): %s\n",
               patch->address, patch->size,
               patch->description ? patch->description : "");

        /* Use WASM host for COW patch application */
        if (e9wasm_apply_patch((void *)g_studio->binary->data, offset,
                               patch->new_bytes, patch->size) == 0) {
            applied++;
        }
    }

    /* Flush instruction cache */
    if (applied > 0) {
        e9wasm_flush_icache((void *)g_studio->binary->data, g_studio->binary->size);
    }

    g_studio->patches_modified = false;
    return applied;
}

int e9studio_save_patched_binary(const char *output_path)
{
    if (!g_studio || !g_studio->binary || !output_path) return -1;

    FILE *fp = fopen(output_path, "wb");
    if (!fp) {
        fprintf(stderr, "Cannot create output file: %s\n", output_path);
        return -1;
    }

    size_t written = fwrite(g_studio->binary->data, 1, g_studio->binary->size, fp);
    fclose(fp);

    if (written != g_studio->binary->size) {
        fprintf(stderr, "Write incomplete: %zu / %zu bytes\n", written, g_studio->binary->size);
        return -1;
    }

    printf("Saved patched binary to %s\n", output_path);
    return 0;
}

int e9studio_save_to_zipos(const char *zip_name)
{
    if (!g_studio || !g_studio->binary || !zip_name) return -1;

    return e9wasm_zipos_append(zip_name, g_studio->binary->data, g_studio->binary->size);
}

/*
 * ============================================================================
 * CFG Export
 * ============================================================================
 */

int e9studio_export_cfg(const char *func_name, const char *output_path)
{
    if (!g_studio || !g_studio->binary || !output_path) return -1;

    E9Function *func = func_name ?
        e9_function_by_name(g_studio->binary, func_name) :
        g_studio->current_func;

    if (!func) return -1;

    if (!func->cfg) {
        func->cfg = e9_cfg_build(g_studio->binary, func);
    }

    if (!func->cfg) return -1;

    return e9_cfg_to_dot(func->cfg, output_path);
}

/*
 * ============================================================================
 * Symbol Import/Export
 * ============================================================================
 */

int e9studio_export_symbols(const char *output_path, const char *format)
{
    if (!g_studio || !g_studio->binary || !output_path) return -1;

    return e9_symbols_export(g_studio->binary, output_path, format ? format : "ghidra");
}

int e9studio_import_symbols(const char *input_path)
{
    if (!g_studio || !g_studio->binary || !input_path) return -1;

    return e9_symbols_import(g_studio->binary, input_path);
}

/*
 * ============================================================================
 * Statistics and Info
 * ============================================================================
 */

void e9studio_print_info(void)
{
    if (!g_studio || !g_studio->binary) {
        printf("No binary loaded\n");
        return;
    }

    E9Binary *bin = g_studio->binary;

    printf("\n=== Binary Analysis Info ===\n");
    printf("Format:      %s\n",
           bin->format == E9_FORMAT_ELF ? "ELF" :
           bin->format == E9_FORMAT_PE ? "PE" :
           bin->format == E9_FORMAT_MACHO ? "Mach-O" : "Raw");
    printf("Arch:        %s\n",
           bin->arch == E9_ARCH_X86_64 ? "x86-64" :
           bin->arch == E9_ARCH_AARCH64 ? "AArch64" : "Unknown");
    printf("Size:        %zu bytes\n", bin->size);
    printf("Base:        0x%lx\n", bin->base_address);
    printf("Entry:       0x%lx\n", bin->entry_point);
    printf("PIE:         %s\n", bin->is_pie ? "yes" : "no");
    printf("Debug info:  %s\n", bin->has_debug_info ? "yes" : "no");
    printf("Sections:    %u\n", bin->num_sections);
    printf("Symbols:     %u\n", bin->num_symbols);
    printf("Functions:   %u\n", bin->num_functions);

    if (g_studio->current_func) {
        printf("\n=== Current Function ===\n");
        printf("Name:        %s\n", g_studio->current_func->name ?
               g_studio->current_func->name : "<unknown>");
        printf("Address:     0x%lx\n", g_studio->current_func->address);
        printf("Size:        %u bytes\n", g_studio->current_func->size);
        if (g_studio->current_func->cfg) {
            printf("Blocks:      %u\n", g_studio->current_func->cfg->num_blocks);
            printf("Complexity:  %u\n", g_studio->current_func->cfg->cyclomatic_complexity);
        }
    }

    if (g_studio->pending_patches && g_studio->pending_patches->num_patches > 0) {
        printf("\n=== Pending Patches ===\n");
        printf("Count:       %u\n", g_studio->pending_patches->num_patches);
    }

    printf("\n");
}

/*
 * ============================================================================
 * Quick Analysis Commands (for TUI integration)
 * ============================================================================
 */

int e9studio_analyze_at(uint64_t addr)
{
    if (!g_studio || !g_studio->binary) return -1;

    /* Check if address is in a function */
    E9Function *func = e9_function_at(g_studio->binary, addr);

    if (!func) {
        /* Try to discover function at this address */
        func = e9_function_add(g_studio->binary, addr, NULL);
        if (func) {
            func->cfg = e9_cfg_build(g_studio->binary, func);
            e9_symbols_auto(g_studio->binary);
        }
    }

    if (func) {
        g_studio->current_func = func;
        g_studio->view_addr = addr;

        /* Ensure CFG is built */
        if (!func->cfg) {
            func->cfg = e9_cfg_build(g_studio->binary, func);
        }

        return 0;
    }

    return -1;
}

const char *e9studio_quick_disasm(uint64_t addr, char *buf, size_t buf_size)
{
    if (!g_studio || !g_studio->binary || !buf) return "";

    E9Instruction *insn = e9_disasm_one(g_studio->binary, addr);
    if (!insn) {
        snprintf(buf, buf_size, "???");
        return buf;
    }

    e9_disasm_str(g_studio->binary, insn, buf, buf_size);
    free(insn);
    return buf;
}

/*
 * ============================================================================
 * Cross-reference Analysis
 * ============================================================================
 */

int e9studio_find_xrefs_to(uint64_t addr, uint64_t *results, int max_results)
{
    if (!g_studio || !g_studio->binary || !results || max_results <= 0) return 0;

    int count = 0;

    /* Search all functions for references to addr */
    E9Function *func = g_studio->binary->functions;
    while (func && count < max_results) {
        if (!func->cfg) continue;

        for (uint32_t i = 0; i < func->cfg->num_blocks && count < max_results; i++) {
            E9BasicBlock *block = func->cfg->blocks[i];
            E9Instruction *insn = block->first;

            while (insn && count < max_results) {
                if (insn->target == addr) {
                    results[count++] = insn->address;
                }
                insn = insn->next;
            }
        }
        func = func->next;
    }

    return count;
}

int e9studio_find_calls_from(uint64_t func_addr, uint64_t *results, int max_results)
{
    if (!g_studio || !g_studio->binary || !results || max_results <= 0) return 0;

    E9Function *func = e9_function_at(g_studio->binary, func_addr);
    if (!func || !func->cfg) return 0;

    int count = 0;

    for (uint32_t i = 0; i < func->cfg->num_blocks && count < max_results; i++) {
        E9BasicBlock *block = func->cfg->blocks[i];
        E9Instruction *insn = block->first;

        while (insn && count < max_results) {
            if (insn->category == E9_INSN_CALL && !insn->target_is_indirect) {
                results[count++] = insn->target;
            }
            insn = insn->next;
        }
    }

    return count;
}
