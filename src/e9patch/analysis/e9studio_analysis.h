/*
 * e9studio_analysis.h
 * Integration layer between E9Analysis engine and E9Studio
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

#ifndef E9STUDIO_ANALYSIS_H
#define E9STUDIO_ANALYSIS_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Initialization and Shutdown
 */
int e9studio_analysis_init(void);
void e9studio_analysis_shutdown(void);

/*
 * Binary Loading
 */
int e9studio_load_binary(const char *path);
int e9studio_load_from_zipos(const char *zip_path);

/*
 * Navigation
 */
int e9studio_goto_address(uint64_t addr);
int e9studio_goto_function(const char *name);
int e9studio_next_function(void);
int e9studio_prev_function(void);

/*
 * View Generation
 */
const char *e9studio_get_disassembly(uint64_t addr, int num_lines, char *buf, size_t buf_size);
const char *e9studio_get_decompiled(const char *func_name, char *buf, size_t buf_size);
const char *e9studio_get_hex_view(uint64_t addr, int num_rows, char *buf, size_t buf_size);

/*
 * Source Code Integration
 */
int e9studio_set_source_file(const char *path);
int e9studio_source_line_to_address(uint32_t line, uint64_t *addr);
int e9studio_address_to_source_line(uint64_t addr, char *file, size_t file_size, uint32_t *line);

/*
 * Live Patching
 */
int e9studio_compile_source(const char *source_path, const char *output_path);
int e9studio_on_source_change(const char *path);
int e9studio_apply_pending_patches(void);
int e9studio_save_patched_binary(const char *output_path);
int e9studio_save_to_zipos(const char *zip_name);

/*
 * CFG and Symbol Export
 */
int e9studio_export_cfg(const char *func_name, const char *output_path);
int e9studio_export_symbols(const char *output_path, const char *format);
int e9studio_import_symbols(const char *input_path);

/*
 * Info and Statistics
 */
void e9studio_print_info(void);

/*
 * Quick Commands
 */
int e9studio_analyze_at(uint64_t addr);
const char *e9studio_quick_disasm(uint64_t addr, char *buf, size_t buf_size);

/*
 * Cross-reference Analysis
 */
int e9studio_find_xrefs_to(uint64_t addr, uint64_t *results, int max_results);
int e9studio_find_calls_from(uint64_t func_addr, uint64_t *results, int max_results);

#ifdef __cplusplus
}
#endif

#endif /* E9STUDIO_ANALYSIS_H */
