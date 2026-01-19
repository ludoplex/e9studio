/*
 * wasm_runtime_common.c
 * WAMR Runtime Core Implementation (Stub)
 *
 * This is a stub implementation of the WAMR runtime API.
 * It provides the minimal functionality needed for E9Studio development
 * while the full WAMR integration is completed.
 *
 * TODO: Replace with actual WAMR source from:
 * https://github.com/bytecodealliance/wasm-micro-runtime
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: Apache-2.0 (WAMR) / GPLv3+ (E9Studio integration)
 */

#include "../include/wasm_export.h"
#include "../../shared/platform/cosmopolitan/platform_internal.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/*
 * Runtime state
 */
static struct {
    bool initialized;
    RunningMode running_mode;
    NativeSymbol *native_symbols;
    uint32_t n_native_symbols;
    char *native_module_name;
} g_wamr_state = {0};

/*
 * Module structure (stub)
 */
struct WASMModuleCommon {
    uint8_t *wasm_bytes;
    uint32_t wasm_size;
    bool is_aot;
};

/*
 * Module instance structure (stub)
 */
struct WASMModuleInstanceCommon {
    struct WASMModuleCommon *module;
    uint8_t *memory;
    uint32_t memory_size;
    uint32_t stack_size;
    uint32_t heap_size;
    char *exception;
};

/*
 * Execution environment (stub)
 */
struct WASMExecEnv {
    struct WASMModuleInstanceCommon *module_inst;
    uint32_t stack_size;
};

/*
 * Function instance (stub)
 */
struct WASMFunctionInstanceCommon {
    const char *name;
    void *func_ptr;
};

/*
 * ============================================================================
 * Runtime initialization
 * ============================================================================
 */

bool wasm_runtime_full_init(RuntimeInitArgs *init_args)
{
    if (g_wamr_state.initialized) {
        LOG_WARNING("WAMR already initialized");
        return true;
    }

    g_wamr_state.running_mode = init_args ? init_args->running_mode : Mode_Default;

    if (g_wamr_state.running_mode == Mode_Default) {
#if WASM_ENABLE_FAST_JIT
        if (os_jit_available()) {
            g_wamr_state.running_mode = Mode_Fast_JIT;
            LOG_DEBUG("Using Fast JIT mode");
        } else
#endif
        {
#if WASM_ENABLE_FAST_INTERP
            g_wamr_state.running_mode = Mode_Fast_Interp;
            LOG_DEBUG("Using Fast Interpreter mode");
#else
            g_wamr_state.running_mode = Mode_Interp;
            LOG_DEBUG("Using Classic Interpreter mode");
#endif
        }
    }

    g_wamr_state.initialized = true;
    LOG_DEBUG("WAMR runtime initialized (mode=%d)", g_wamr_state.running_mode);

    return true;
}

bool wasm_runtime_init(void)
{
    RuntimeInitArgs args = {0};
    args.mem_alloc_type = Alloc_With_System_Allocator;
    args.running_mode = Mode_Default;
    return wasm_runtime_full_init(&args);
}

void wasm_runtime_destroy(void)
{
    if (!g_wamr_state.initialized)
        return;

    if (g_wamr_state.native_symbols) {
        os_free(g_wamr_state.native_symbols);
        g_wamr_state.native_symbols = NULL;
    }
    if (g_wamr_state.native_module_name) {
        os_free(g_wamr_state.native_module_name);
        g_wamr_state.native_module_name = NULL;
    }

    g_wamr_state.initialized = false;
    LOG_DEBUG("WAMR runtime destroyed");
}

bool wasm_runtime_set_running_mode(RunningMode mode)
{
    switch (mode) {
        case Mode_Interp:
#if !WASM_ENABLE_INTERP
            LOG_ERROR("Interpreter mode not enabled in build");
            return false;
#endif
            break;
        case Mode_Fast_Interp:
#if !WASM_ENABLE_FAST_INTERP
            LOG_ERROR("Fast interpreter mode not enabled in build");
            return false;
#endif
            break;
        case Mode_Fast_JIT:
#if !WASM_ENABLE_FAST_JIT
            LOG_ERROR("Fast JIT mode not enabled in build");
            return false;
#else
            if (!os_jit_available()) {
                LOG_ERROR("JIT not available on this platform");
                return false;
            }
#endif
            break;
        case Mode_LLVM_AOT:
#if !WASM_ENABLE_AOT
            LOG_ERROR("AOT mode not enabled in build");
            return false;
#endif
            break;
        default:
            break;
    }

    g_wamr_state.running_mode = mode;
    return true;
}

RunningMode wasm_runtime_get_running_mode(void)
{
    return g_wamr_state.running_mode;
}

/*
 * ============================================================================
 * Native symbol registration
 * ============================================================================
 */

bool wasm_runtime_register_natives(const char *module_name,
                                    NativeSymbol *native_symbols,
                                    uint32_t n_native_symbols)
{
    if (!module_name || !native_symbols || n_native_symbols == 0)
        return false;

    /* Store for later use during instantiation */
    g_wamr_state.native_module_name = os_malloc(strlen(module_name) + 1);
    if (!g_wamr_state.native_module_name)
        return false;
    strcpy(g_wamr_state.native_module_name, module_name);

    g_wamr_state.native_symbols = os_malloc(n_native_symbols * sizeof(NativeSymbol));
    if (!g_wamr_state.native_symbols) {
        os_free(g_wamr_state.native_module_name);
        return false;
    }
    memcpy(g_wamr_state.native_symbols, native_symbols,
           n_native_symbols * sizeof(NativeSymbol));
    g_wamr_state.n_native_symbols = n_native_symbols;

    LOG_DEBUG("Registered %u native symbols for module '%s'",
              n_native_symbols, module_name);

    return true;
}

bool wasm_runtime_register_natives_raw(const char *module_name,
                                        NativeSymbol *native_symbols,
                                        uint32_t n_native_symbols)
{
    return wasm_runtime_register_natives(module_name, native_symbols, n_native_symbols);
}

/*
 * ============================================================================
 * Module loading (stub - returns error)
 * ============================================================================
 */

wasm_module_t wasm_runtime_load(uint8_t *buf, uint32_t size,
                                 char *error_buf, uint32_t error_buf_size)
{
    if (!buf || size < 8) {
        if (error_buf && error_buf_size > 0)
            snprintf(error_buf, error_buf_size, "Invalid WASM buffer");
        return NULL;
    }

    /* Check WASM magic number */
    if (buf[0] != 0x00 || buf[1] != 0x61 || buf[2] != 0x73 || buf[3] != 0x6D) {
        if (error_buf && error_buf_size > 0)
            snprintf(error_buf, error_buf_size, "Invalid WASM magic number");
        return NULL;
    }

    /* Allocate module */
    struct WASMModuleCommon *module = os_malloc(sizeof(struct WASMModuleCommon));
    if (!module) {
        if (error_buf && error_buf_size > 0)
            snprintf(error_buf, error_buf_size, "Out of memory");
        return NULL;
    }

    /* Copy WASM bytes */
    module->wasm_bytes = os_malloc(size);
    if (!module->wasm_bytes) {
        os_free(module);
        if (error_buf && error_buf_size > 0)
            snprintf(error_buf, error_buf_size, "Out of memory");
        return NULL;
    }
    memcpy(module->wasm_bytes, buf, size);
    module->wasm_size = size;
    module->is_aot = false;

    LOG_DEBUG("Loaded WASM module (%u bytes)", size);

    /*
     * TODO: Actual WASM parsing and validation
     * This stub just stores the bytes for now
     */

    return module;
}

wasm_module_t wasm_runtime_load_aot(uint8_t *buf, uint32_t size,
                                     char *error_buf, uint32_t error_buf_size)
{
    /* AOT modules have different magic */
    if (!buf || size < 8) {
        if (error_buf && error_buf_size > 0)
            snprintf(error_buf, error_buf_size, "Invalid AOT buffer");
        return NULL;
    }

    struct WASMModuleCommon *module = os_malloc(sizeof(struct WASMModuleCommon));
    if (!module) {
        if (error_buf && error_buf_size > 0)
            snprintf(error_buf, error_buf_size, "Out of memory");
        return NULL;
    }

    module->wasm_bytes = os_malloc(size);
    if (!module->wasm_bytes) {
        os_free(module);
        if (error_buf && error_buf_size > 0)
            snprintf(error_buf, error_buf_size, "Out of memory");
        return NULL;
    }
    memcpy(module->wasm_bytes, buf, size);
    module->wasm_size = size;
    module->is_aot = true;

    LOG_DEBUG("Loaded AOT module (%u bytes)", size);

    return module;
}

void wasm_runtime_unload(wasm_module_t module)
{
    if (!module)
        return;

    struct WASMModuleCommon *m = (struct WASMModuleCommon *)module;
    if (m->wasm_bytes)
        os_free(m->wasm_bytes);
    os_free(m);

    LOG_DEBUG("Unloaded module");
}

/*
 * ============================================================================
 * Module instantiation (stub)
 * ============================================================================
 */

wasm_module_inst_t wasm_runtime_instantiate(wasm_module_t module,
                                             uint32_t stack_size,
                                             uint32_t heap_size,
                                             char *error_buf,
                                             uint32_t error_buf_size)
{
    if (!module) {
        if (error_buf && error_buf_size > 0)
            snprintf(error_buf, error_buf_size, "Invalid module");
        return NULL;
    }

    struct WASMModuleInstanceCommon *inst = os_malloc(sizeof(*inst));
    if (!inst) {
        if (error_buf && error_buf_size > 0)
            snprintf(error_buf, error_buf_size, "Out of memory");
        return NULL;
    }

    inst->module = (struct WASMModuleCommon *)module;
    inst->stack_size = stack_size ? stack_size : 64 * 1024;
    inst->heap_size = heap_size ? heap_size : 16 * 1024 * 1024;
    inst->exception = NULL;

    /* Allocate linear memory */
    inst->memory_size = inst->heap_size;
    inst->memory = os_mmap(NULL, inst->memory_size,
                           PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS);
    if (!inst->memory) {
        os_free(inst);
        if (error_buf && error_buf_size > 0)
            snprintf(error_buf, error_buf_size, "Failed to allocate memory");
        return NULL;
    }

    LOG_DEBUG("Instantiated module (stack=%u, heap=%u)", stack_size, heap_size);

    return inst;
}

void wasm_runtime_deinstantiate(wasm_module_inst_t module_inst)
{
    if (!module_inst)
        return;

    struct WASMModuleInstanceCommon *inst = (struct WASMModuleInstanceCommon *)module_inst;

    if (inst->memory)
        os_munmap(inst->memory, inst->memory_size);
    if (inst->exception)
        os_free(inst->exception);
    os_free(inst);

    LOG_DEBUG("Deinstantiated module");
}

/*
 * ============================================================================
 * Execution environment
 * ============================================================================
 */

wasm_exec_env_t wasm_runtime_create_exec_env(wasm_module_inst_t module_inst,
                                              uint32_t stack_size)
{
    if (!module_inst)
        return NULL;

    struct WASMExecEnv *env = os_malloc(sizeof(*env));
    if (!env)
        return NULL;

    env->module_inst = (struct WASMModuleInstanceCommon *)module_inst;
    env->stack_size = stack_size ? stack_size : 64 * 1024;

    LOG_DEBUG("Created exec env (stack=%u)", stack_size);

    return env;
}

void wasm_runtime_destroy_exec_env(wasm_exec_env_t exec_env)
{
    if (exec_env)
        os_free(exec_env);
}

wasm_module_inst_t wasm_runtime_get_module_inst(wasm_exec_env_t exec_env)
{
    if (!exec_env)
        return NULL;
    return (wasm_module_inst_t)((struct WASMExecEnv *)exec_env)->module_inst;
}

/*
 * ============================================================================
 * Function execution (stub - returns error)
 * ============================================================================
 */

wasm_function_inst_t wasm_runtime_lookup_function(wasm_module_inst_t module_inst,
                                                   const char *name)
{
    (void)module_inst;
    (void)name;

    /*
     * TODO: Implement actual function lookup
     * For now, return NULL (function not found)
     */
    LOG_WARNING("Function lookup not implemented: %s", name ? name : "(null)");
    return NULL;
}

bool wasm_runtime_call_wasm(wasm_exec_env_t exec_env,
                            wasm_function_inst_t function,
                            uint32_t argc, uint32_t argv[])
{
    (void)exec_env;
    (void)function;
    (void)argc;
    (void)argv;

    /*
     * TODO: Implement actual WASM execution
     */
    LOG_WARNING("WASM execution not implemented (stub runtime)");
    return false;
}

bool wasm_runtime_call_wasm_a(wasm_exec_env_t exec_env,
                               wasm_function_inst_t function,
                               uint32_t num_results, wasm_val_t results[],
                               uint32_t num_args, wasm_val_t args[])
{
    (void)exec_env;
    (void)function;
    (void)num_results;
    (void)results;
    (void)num_args;
    (void)args;

    LOG_WARNING("WASM execution not implemented (stub runtime)");
    return false;
}

const char *wasm_runtime_get_exception(wasm_module_inst_t module_inst)
{
    if (!module_inst)
        return NULL;
    return ((struct WASMModuleInstanceCommon *)module_inst)->exception;
}

void wasm_runtime_clear_exception(wasm_module_inst_t module_inst)
{
    if (!module_inst)
        return;
    struct WASMModuleInstanceCommon *inst = (struct WASMModuleInstanceCommon *)module_inst;
    if (inst->exception) {
        os_free(inst->exception);
        inst->exception = NULL;
    }
}

/*
 * ============================================================================
 * Memory access
 * ============================================================================
 */

bool wasm_runtime_validate_app_addr(wasm_module_inst_t module_inst,
                                     uint32_t app_offset, uint32_t size)
{
    if (!module_inst)
        return false;
    struct WASMModuleInstanceCommon *inst = (struct WASMModuleInstanceCommon *)module_inst;
    return (app_offset + size <= inst->memory_size);
}

bool wasm_runtime_validate_native_addr(wasm_module_inst_t module_inst,
                                        void *native_ptr, uint32_t size)
{
    if (!module_inst || !native_ptr)
        return false;
    struct WASMModuleInstanceCommon *inst = (struct WASMModuleInstanceCommon *)module_inst;
    uint8_t *ptr = (uint8_t *)native_ptr;
    return (ptr >= inst->memory && ptr + size <= inst->memory + inst->memory_size);
}

void *wasm_runtime_addr_app_to_native(wasm_module_inst_t module_inst,
                                       uint32_t app_offset)
{
    if (!module_inst)
        return NULL;
    struct WASMModuleInstanceCommon *inst = (struct WASMModuleInstanceCommon *)module_inst;
    if (app_offset >= inst->memory_size)
        return NULL;
    return inst->memory + app_offset;
}

uint32_t wasm_runtime_addr_native_to_app(wasm_module_inst_t module_inst,
                                          void *native_ptr)
{
    if (!module_inst || !native_ptr)
        return 0;
    struct WASMModuleInstanceCommon *inst = (struct WASMModuleInstanceCommon *)module_inst;
    uint8_t *ptr = (uint8_t *)native_ptr;
    if (ptr < inst->memory || ptr >= inst->memory + inst->memory_size)
        return 0;
    return (uint32_t)(ptr - inst->memory);
}

uint8_t *wasm_runtime_get_memory_base(wasm_module_inst_t module_inst)
{
    if (!module_inst)
        return NULL;
    return ((struct WASMModuleInstanceCommon *)module_inst)->memory;
}

uint32_t wasm_runtime_get_memory_size(wasm_module_inst_t module_inst)
{
    if (!module_inst)
        return 0;
    return ((struct WASMModuleInstanceCommon *)module_inst)->memory_size;
}

/*
 * ============================================================================
 * Module memory management
 * ============================================================================
 */

uint32_t wasm_runtime_module_malloc(wasm_module_inst_t module_inst,
                                     uint32_t size, void **p_native_addr)
{
    /*
     * TODO: Implement proper heap allocator
     * For now, use a simple bump allocator from the end of memory
     */
    (void)module_inst;
    (void)size;
    (void)p_native_addr;
    LOG_WARNING("module_malloc not implemented");
    return 0;
}

void wasm_runtime_module_free(wasm_module_inst_t module_inst, uint32_t ptr)
{
    (void)module_inst;
    (void)ptr;
    /* TODO: Implement */
}

uint32_t wasm_runtime_module_dup_data(wasm_module_inst_t module_inst,
                                       const char *src, uint32_t size)
{
    (void)module_inst;
    (void)src;
    (void)size;
    LOG_WARNING("module_dup_data not implemented");
    return 0;
}
