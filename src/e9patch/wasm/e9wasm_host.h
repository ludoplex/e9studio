/*
 * e9wasm_host.h
 * Embedded WASM VM Host for e9patch
 *
 * Replaces Chrome/browser as the WASM runtime. Uses WAMR (WebAssembly
 * Micro Runtime) with Fast JIT for high-performance execution.
 *
 * Execution modes:
 *   - Fast Interpreter: Portable, moderate speed
 *   - Fast JIT: JIT compilation without LLVM, best performance
 *   - AOT: Pre-compiled native code for maximum performance
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

#ifndef E9WASM_HOST_H
#define E9WASM_HOST_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * WASM Runtime Configuration
 */
typedef struct {
    size_t stack_size;          /* WASM stack size (default: 64KB) */
    size_t heap_size;           /* WASM heap size (default: 16MB) */
    size_t shared_buffer_size;  /* Shared buffer for binary data (default: 64MB) */
    bool enable_wasi;           /* Enable WASI imports */
    bool enable_debug;          /* Enable debug logging */
    const char *module_path;    /* Path to main WASM module (in ZipOS) */
} E9WasmConfig;

/*
 * Set execution mode (call BEFORE e9wasm_init)
 * mode: 0=interpreter, 1=fast_jit (default), 2=aot
 */
void e9wasm_set_exec_mode(int mode);

/*
 * Initialize WASM runtime
 * Returns 0 on success, -1 on error
 */
int e9wasm_init(const E9WasmConfig *config);

/*
 * Shutdown WASM runtime
 */
void e9wasm_shutdown(void);

/*
 * Load and instantiate a WASM module from ZipOS
 * Returns module handle or NULL on error
 */
void *e9wasm_load_module(const char *path);

/*
 * Call exported WASM function
 * Returns 0 on success, -1 on error
 */
int e9wasm_call(void *module, const char *func_name, int argc, const char *argv[]);

/*
 * Get pointer to shared buffer (accessible from both host and WASM)
 * This buffer is used for passing binary data without copies
 */
uint8_t *e9wasm_get_shared_buffer(size_t *out_size);

/*
 * Load binary from ZipOS into shared buffer
 * Returns size loaded, or 0 on error
 */
size_t e9wasm_load_binary(const char *zip_path);

/*
 * Memory-map binary from ZipOS directly (zero-copy)
 * Returns mapped address or NULL on error
 */
void *e9wasm_mmap_binary(const char *zip_path, size_t *out_size, bool writable);

/*
 * Unmap previously mapped binary
 */
void e9wasm_munmap_binary(void *addr, size_t size);

/*
 * Apply patch to mapped binary
 * offset: offset into mapped region
 * data: patch bytes
 * size: number of bytes to patch
 * Returns 0 on success, -1 on error
 */
int e9wasm_apply_patch(void *mapped, size_t offset, const uint8_t *data, size_t size);

/*
 * Flush instruction cache (required after patching executable code)
 */
void e9wasm_flush_icache(void *addr, size_t size);

/*
 * Register callback for file change notifications
 */
typedef void (*E9WasmFileCallback)(const char *path, void *userdata);
int e9wasm_watch_file(const char *path, E9WasmFileCallback callback, void *userdata);

/*
 * Register callback for WASM->host notifications
 */
typedef void (*E9WasmEventCallback)(const char *event, const char *data, void *userdata);
void e9wasm_set_event_callback(E9WasmEventCallback callback, void *userdata);

/*
 * TUI functions for embedded terminal interface
 */
int e9wasm_tui_init(void);
void e9wasm_tui_shutdown(void);
void e9wasm_tui_refresh(void);
int e9wasm_tui_get_key(void);
void e9wasm_tui_print(int row, int col, const char *text);
void e9wasm_tui_clear(void);

/*
 * ZipOS manipulation (for self-modifying APE)
 */

/*
 * Append file to own ZipOS
 * This allows the APE to save patched binaries inside itself
 */
int e9wasm_zipos_append(const char *name, const uint8_t *data, size_t size);

/*
 * List files in ZipOS
 * callback receives each filename; return non-zero to stop iteration
 */
typedef int (*E9WasmZipCallback)(const char *name, size_t size, void *userdata);
int e9wasm_zipos_list(E9WasmZipCallback callback, void *userdata);

/*
 * Get path to executable (for self-modification)
 */
const char *e9wasm_get_exe_path(void);

/*
 * Embedded ZipOS support (works without Cosmopolitan)
 * Reads ZIP content appended to the executable
 */

/*
 * Check if embedded ZipOS is available
 * Returns 1 if available, 0 otherwise
 */
int e9wasm_zipos_available(void);

/*
 * Read file from embedded ZipOS
 * Returns allocated buffer (caller must free) or NULL on error
 * Sets *out_size to file size
 */
uint8_t *e9wasm_zipos_read(const char *name, size_t *out_size);

#ifdef __cplusplus
}
#endif

#endif /* E9WASM_HOST_H */
