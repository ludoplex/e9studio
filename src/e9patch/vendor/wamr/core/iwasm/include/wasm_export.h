/*
 * wasm_export.h
 * WAMR Public API Header
 *
 * This defines the public interface for WAMR (WebAssembly Micro Runtime).
 * E9Studio uses this API to load and execute WASM modules.
 *
 * Reference: https://github.com/bytecodealliance/wasm-micro-runtime
 * License: Apache-2.0
 */

#ifndef WASM_EXPORT_H
#define WASM_EXPORT_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Opaque types
 */
typedef struct WASMModuleCommon *wasm_module_t;
typedef struct WASMModuleInstanceCommon *wasm_module_inst_t;
typedef struct WASMExecEnv *wasm_exec_env_t;
typedef struct WASMFunctionInstanceCommon *wasm_function_inst_t;

/*
 * Running modes
 */
typedef enum RunningMode {
    Mode_Interp = 1,       /* Classic interpreter */
    Mode_Fast_Interp = 2,  /* Fast interpreter */
    Mode_LLVM_AOT = 3,     /* LLVM AOT */
    Mode_Fast_JIT = 4,     /* Fast JIT (no LLVM) */
    Mode_Multi_Tier_JIT = 5, /* Multi-tier JIT */
    Mode_Default = 0       /* Use default based on build config */
} RunningMode;

/*
 * Memory allocation type
 */
typedef enum {
    Alloc_With_Pool = 0,           /* Use memory pool */
    Alloc_With_Allocator = 1,      /* Use custom allocator */
    Alloc_With_System_Allocator = 2 /* Use system malloc/free */
} mem_alloc_type_t;

/*
 * Memory allocator functions
 */
typedef void *(*malloc_func_t)(unsigned int size);
typedef void *(*realloc_func_t)(void *ptr, unsigned int size);
typedef void (*free_func_t)(void *ptr);

typedef struct MemAllocOption {
    mem_alloc_type_t mem_alloc_type;
    union {
        struct {
            void *heap_buf;
            uint32_t heap_size;
        } pool;
        struct {
            malloc_func_t malloc_func;
            realloc_func_t realloc_func;
            free_func_t free_func;
        } allocator;
    } mem_alloc_option;
} MemAllocOption;

/*
 * Runtime initialization arguments
 */
typedef struct RuntimeInitArgs {
    mem_alloc_type_t mem_alloc_type;
    MemAllocOption mem_alloc_option;

    /* Running mode */
    RunningMode running_mode;

    /* Platform native stack info */
    const char *native_module_name;
    void *native_symbols;
    uint32_t n_native_symbols;

    /* Max thread number */
    uint32_t max_thread_num;

    /* Reserved */
    void *reserved[8];
} RuntimeInitArgs;

/*
 * Native symbol for host function registration
 */
typedef struct NativeSymbol {
    const char *symbol;      /* Function name */
    void *func_ptr;          /* Function pointer */
    const char *signature;   /* WAMR signature string */
    void *attachment;        /* User data */
} NativeSymbol;

/*
 * Value types for function calls
 */
typedef enum {
    WASM_I32 = 0x7F,
    WASM_I64 = 0x7E,
    WASM_F32 = 0x7D,
    WASM_F64 = 0x7C,
    WASM_EXTERNREF = 0x6F,
    WASM_FUNCREF = 0x70
} wasm_valkind_t;

typedef union {
    int32_t i32;
    int64_t i64;
    float f32;
    double f64;
} wasm_val_t;

/*
 * ============================================================================
 * Runtime initialization and destruction
 * ============================================================================
 */

/**
 * Initialize WASM runtime environment with full configuration
 * @param init_args initialization arguments
 * @return true on success, false on failure
 */
bool wasm_runtime_full_init(RuntimeInitArgs *init_args);

/**
 * Initialize WASM runtime environment with default settings
 * @return true on success, false on failure
 */
bool wasm_runtime_init(void);

/**
 * Destroy WASM runtime environment
 */
void wasm_runtime_destroy(void);

/**
 * Set running mode for the runtime
 * @param mode running mode to set
 * @return true if mode is supported and set, false otherwise
 */
bool wasm_runtime_set_running_mode(RunningMode mode);

/**
 * Get current running mode
 * @return current running mode
 */
RunningMode wasm_runtime_get_running_mode(void);

/*
 * ============================================================================
 * Native symbol registration
 * ============================================================================
 */

/**
 * Register native functions that can be called from WASM
 * @param module_name module name for the native functions
 * @param native_symbols array of native symbol definitions
 * @param n_native_symbols number of symbols in the array
 * @return true on success, false on failure
 */
bool wasm_runtime_register_natives(const char *module_name,
                                    NativeSymbol *native_symbols,
                                    uint32_t n_native_symbols);

/**
 * Register native functions with raw call interface
 * @param module_name module name for the native functions
 * @param native_symbols array of native symbol definitions
 * @param n_native_symbols number of symbols in the array
 * @return true on success, false on failure
 */
bool wasm_runtime_register_natives_raw(const char *module_name,
                                        NativeSymbol *native_symbols,
                                        uint32_t n_native_symbols);

/*
 * ============================================================================
 * Module loading and instantiation
 * ============================================================================
 */

/**
 * Load WASM module from binary buffer
 * @param buf WASM binary buffer
 * @param size buffer size
 * @param error_buf buffer to store error message
 * @param error_buf_size error buffer size
 * @return module handle on success, NULL on failure
 */
wasm_module_t wasm_runtime_load(uint8_t *buf, uint32_t size,
                                 char *error_buf, uint32_t error_buf_size);

/**
 * Load AOT module from binary buffer
 * @param buf AOT binary buffer
 * @param size buffer size
 * @param error_buf buffer to store error message
 * @param error_buf_size error buffer size
 * @return module handle on success, NULL on failure
 */
wasm_module_t wasm_runtime_load_aot(uint8_t *buf, uint32_t size,
                                     char *error_buf, uint32_t error_buf_size);

/**
 * Unload WASM module
 * @param module module handle to unload
 */
void wasm_runtime_unload(wasm_module_t module);

/**
 * Instantiate a loaded WASM module
 * @param module loaded module
 * @param stack_size WASM stack size
 * @param heap_size WASM heap size
 * @param error_buf buffer to store error message
 * @param error_buf_size error buffer size
 * @return module instance on success, NULL on failure
 */
wasm_module_inst_t wasm_runtime_instantiate(wasm_module_t module,
                                             uint32_t stack_size,
                                             uint32_t heap_size,
                                             char *error_buf,
                                             uint32_t error_buf_size);

/**
 * Deinstantiate a module instance
 * @param module_inst module instance to destroy
 */
void wasm_runtime_deinstantiate(wasm_module_inst_t module_inst);

/*
 * ============================================================================
 * Execution environment
 * ============================================================================
 */

/**
 * Create execution environment for a module instance
 * @param module_inst module instance
 * @param stack_size native stack size for the execution environment
 * @return execution environment on success, NULL on failure
 */
wasm_exec_env_t wasm_runtime_create_exec_env(wasm_module_inst_t module_inst,
                                              uint32_t stack_size);

/**
 * Destroy execution environment
 * @param exec_env execution environment to destroy
 */
void wasm_runtime_destroy_exec_env(wasm_exec_env_t exec_env);

/**
 * Get module instance from execution environment
 * @param exec_env execution environment
 * @return module instance
 */
wasm_module_inst_t wasm_runtime_get_module_inst(wasm_exec_env_t exec_env);

/*
 * ============================================================================
 * Function lookup and execution
 * ============================================================================
 */

/**
 * Lookup exported function by name
 * @param module_inst module instance
 * @param name function name
 * @return function instance on success, NULL if not found
 */
wasm_function_inst_t wasm_runtime_lookup_function(wasm_module_inst_t module_inst,
                                                   const char *name);

/**
 * Call WASM function
 * @param exec_env execution environment
 * @param function function to call
 * @param argc number of arguments
 * @param argv argument values (also receives return value)
 * @return true on success, false on failure
 */
bool wasm_runtime_call_wasm(wasm_exec_env_t exec_env,
                            wasm_function_inst_t function,
                            uint32_t argc, uint32_t argv[]);

/**
 * Call WASM function with typed arguments
 * @param exec_env execution environment
 * @param function function to call
 * @param num_results number of results
 * @param results array to store results
 * @param num_args number of arguments
 * @param args argument values
 * @return true on success, false on failure
 */
bool wasm_runtime_call_wasm_a(wasm_exec_env_t exec_env,
                               wasm_function_inst_t function,
                               uint32_t num_results, wasm_val_t results[],
                               uint32_t num_args, wasm_val_t args[]);

/**
 * Get exception message from module instance
 * @param module_inst module instance
 * @return exception message or NULL if no exception
 */
const char *wasm_runtime_get_exception(wasm_module_inst_t module_inst);

/**
 * Clear exception in module instance
 * @param module_inst module instance
 */
void wasm_runtime_clear_exception(wasm_module_inst_t module_inst);

/*
 * ============================================================================
 * Memory access
 * ============================================================================
 */

/**
 * Validate application address range
 * @param module_inst module instance
 * @param app_offset offset in WASM linear memory
 * @param size size in bytes to validate
 * @return true if valid, false otherwise
 */
bool wasm_runtime_validate_app_addr(wasm_module_inst_t module_inst,
                                     uint32_t app_offset, uint32_t size);

/**
 * Validate native address range
 * @param module_inst module instance
 * @param native_ptr native pointer
 * @param size size in bytes to validate
 * @return true if valid, false otherwise
 */
bool wasm_runtime_validate_native_addr(wasm_module_inst_t module_inst,
                                        void *native_ptr, uint32_t size);

/**
 * Convert app address to native address
 * @param module_inst module instance
 * @param app_offset offset in WASM linear memory
 * @return native pointer or NULL if invalid
 */
void *wasm_runtime_addr_app_to_native(wasm_module_inst_t module_inst,
                                       uint32_t app_offset);

/**
 * Convert native address to app address
 * @param module_inst module instance
 * @param native_ptr native pointer
 * @return app offset or 0 if invalid
 */
uint32_t wasm_runtime_addr_native_to_app(wasm_module_inst_t module_inst,
                                          void *native_ptr);

/**
 * Get WASM memory base address
 * @param module_inst module instance
 * @return base address of WASM linear memory
 */
uint8_t *wasm_runtime_get_memory_base(wasm_module_inst_t module_inst);

/**
 * Get WASM memory size
 * @param module_inst module instance
 * @return size of WASM linear memory in bytes
 */
uint32_t wasm_runtime_get_memory_size(wasm_module_inst_t module_inst);

/*
 * ============================================================================
 * Module memory management
 * ============================================================================
 */

/**
 * Allocate memory from module heap
 * @param module_inst module instance
 * @param size size in bytes
 * @param p_native_addr pointer to receive native address (optional)
 * @return app offset or 0 on failure
 */
uint32_t wasm_runtime_module_malloc(wasm_module_inst_t module_inst,
                                     uint32_t size, void **p_native_addr);

/**
 * Free memory from module heap
 * @param module_inst module instance
 * @param ptr app offset to free
 */
void wasm_runtime_module_free(wasm_module_inst_t module_inst, uint32_t ptr);

/**
 * Duplicate bytes into module memory
 * @param module_inst module instance
 * @param src source bytes
 * @param size size in bytes
 * @return app offset or 0 on failure
 */
uint32_t wasm_runtime_module_dup_data(wasm_module_inst_t module_inst,
                                       const char *src, uint32_t size);

#ifdef __cplusplus
}
#endif

#endif /* WASM_EXPORT_H */
