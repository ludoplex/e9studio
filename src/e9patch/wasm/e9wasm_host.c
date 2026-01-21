/*
 * e9wasm_host.c
 * Embedded WASM VM Host Implementation
 *
 * Uses WAMR (WebAssembly Micro Runtime) with Fast JIT for high-performance
 * WASM execution. Replaces Chrome/browser as the WASM runtime.
 *
 * Features:
 * - Fast JIT compilation (no LLVM dependency)
 * - Direct ZipOS integration for embedded files
 * - Shared memory buffer for binary data exchange
 * - Native function registration for host callbacks
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

/* Central config must be included first for feature test macros */
#include "e9studio_config.h"

#include "e9wasm_host.h"

/* WAMR headers */
#include "wasm_export.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#ifdef __COSMOPOLITAN__
#include <cosmo.h>
#endif

/*
 * Execution mode enumeration
 */
typedef enum {
    E9_WASM_MODE_INTERP = 0,     /* Fast interpreter */
    E9_WASM_MODE_FAST_JIT = 1,   /* Fast JIT (default) */
    E9_WASM_MODE_AOT = 2         /* Ahead-of-time compiled */
} E9WasmExecMode;

/*
 * Runtime state
 */
static struct {
    bool initialized;

    /* WAMR state */
    wasm_module_t module;
    wasm_module_inst_t module_inst;
    wasm_exec_env_t exec_env;

    /* Shared buffer for binary data exchange */
    uint8_t *shared_buffer;
    size_t shared_buffer_size;

    /* Currently mapped binary */
    void *mapped_binary;
    size_t mapped_size;
    int mapped_fd;

    /* Executable path for self-modification */
    char exe_path[4096];

    /* Event callback */
    E9WasmEventCallback event_callback;
    void *event_userdata;

    /* Configuration */
    E9WasmConfig config;

    /* Execution mode */
    E9WasmExecMode exec_mode;

} g_runtime = {0};

/*
 * Logging
 */
static void wasm_log(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "[e9wasm] ");
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
}

/*
 * Forward declarations
 */
static int zipos_is_disabled(void);

/*
 * ============================================================================
 * Native host functions (callable from WASM)
 * ============================================================================
 */

/*
 * Native function: read from ZipOS
 * Signature: (i32 name_ptr, i32 name_len, i32 out_buf, i32 buf_size) -> i32
 */
static int32_t native_zipos_read(wasm_exec_env_t exec_env,
                                  int32_t name_ptr, int32_t name_len,
                                  int32_t out_buf, int32_t buf_size)
{
    wasm_module_inst_t inst = wasm_runtime_get_module_inst(exec_env);

    /* Validate pointers */
    if (!wasm_runtime_validate_app_addr(inst, name_ptr, name_len) ||
        !wasm_runtime_validate_app_addr(inst, out_buf, buf_size)) {
        wasm_log("Invalid memory access in zipos_read");
        return -1;
    }

    char *name = wasm_runtime_addr_app_to_native(inst, name_ptr);
    uint8_t *buf = wasm_runtime_addr_app_to_native(inst, out_buf);

    /* Construct path with null terminator */
    char path[512];
    if (name_len >= (int32_t)sizeof(path)) {
        return -1;
    }
    memcpy(path, name, name_len);
    path[name_len] = '\0';

    /* Read from ZipOS */
    size_t size;
    uint8_t *data = e9wasm_zipos_read(path, &size);
    if (!data) {
        return -1;
    }

    if (size > (size_t)buf_size) {
        free(data);
        return -1;
    }

    memcpy(buf, data, size);
    free(data);
    return (int32_t)size;
}

/*
 * Native function: apply patch to shared buffer
 * Signature: (i32 offset, i32 data_ptr, i32 size) -> i32
 */
static int32_t native_apply_patch(wasm_exec_env_t exec_env,
                                   int32_t offset, int32_t data_ptr, int32_t size)
{
    wasm_module_inst_t inst = wasm_runtime_get_module_inst(exec_env);

    if (!wasm_runtime_validate_app_addr(inst, data_ptr, size)) {
        wasm_log("Invalid memory access in apply_patch");
        return -1;
    }

    uint8_t *data = wasm_runtime_addr_app_to_native(inst, data_ptr);

    /* Apply to shared buffer */
    if (!g_runtime.shared_buffer ||
        offset < 0 ||
        (size_t)(offset + size) > g_runtime.shared_buffer_size) {
        wasm_log("Patch out of bounds: offset=%d, size=%d, buffer=%zu",
                 offset, size, g_runtime.shared_buffer_size);
        return -1;
    }

    memcpy(g_runtime.shared_buffer + offset, data, size);
    wasm_log("Applied %d byte patch at offset %d", size, offset);
    return 0;
}

/*
 * Native function: get shared buffer info
 * Signature: (i32 info_ptr) -> i32
 * Writes: { uint32_t offset_in_wasm_memory, uint32_t size }
 */
static int32_t native_get_shared_buffer_info(wasm_exec_env_t exec_env,
                                               int32_t info_ptr)
{
    wasm_module_inst_t inst = wasm_runtime_get_module_inst(exec_env);

    if (!wasm_runtime_validate_app_addr(inst, info_ptr, 8)) {
        return -1;
    }

    uint32_t *info = wasm_runtime_addr_app_to_native(inst, info_ptr);

    /* The shared buffer is at offset 0 in our implementation */
    /* In a real impl, we'd map it into WASM linear memory properly */
    info[0] = 0;  /* offset */
    info[1] = (uint32_t)g_runtime.shared_buffer_size;

    return 0;
}

/*
 * Native function: log message
 * Signature: (i32 msg_ptr, i32 msg_len) -> void
 */
static void native_log(wasm_exec_env_t exec_env,
                       int32_t msg_ptr, int32_t msg_len)
{
    wasm_module_inst_t inst = wasm_runtime_get_module_inst(exec_env);

    if (!wasm_runtime_validate_app_addr(inst, msg_ptr, msg_len)) {
        return;
    }

    char *msg = wasm_runtime_addr_app_to_native(inst, msg_ptr);

    /* Print with length limit */
    fprintf(stderr, "[wasm] %.*s\n", msg_len, msg);
}

/*
 * Native function: flush icache
 * Signature: (i32 addr, i32 size) -> void
 */
static void native_flush_icache(wasm_exec_env_t exec_env,
                                 int32_t addr, int32_t size)
{
    (void)exec_env;

    if (g_runtime.shared_buffer && addr >= 0 &&
        (size_t)(addr + size) <= g_runtime.shared_buffer_size) {
        e9wasm_flush_icache(g_runtime.shared_buffer + addr, size);
    }
}

/*
 * Native symbol registration table
 */
static NativeSymbol g_native_symbols[] = {
    { "zipos_read", native_zipos_read, "(iiii)i", NULL },
    { "apply_patch", native_apply_patch, "(iii)i", NULL },
    { "get_shared_buffer_info", native_get_shared_buffer_info, "(i)i", NULL },
    { "log", native_log, "(ii)", NULL },
    { "flush_icache", native_flush_icache, "(ii)", NULL },
};

/*
 * ============================================================================
 * Runtime initialization
 * ============================================================================
 */

/*
 * Set execution mode (call before e9wasm_init)
 */
void e9wasm_set_exec_mode(int mode)
{
    switch (mode) {
        case 0: g_runtime.exec_mode = E9_WASM_MODE_INTERP; break;
        case 1: g_runtime.exec_mode = E9_WASM_MODE_FAST_JIT; break;
        case 2: g_runtime.exec_mode = E9_WASM_MODE_AOT; break;
        default: g_runtime.exec_mode = E9_WASM_MODE_FAST_JIT; break;
    }
}

int e9wasm_init(const E9WasmConfig *config)
{
    if (g_runtime.initialized) {
        wasm_log("Already initialized");
        return 0;
    }

    wasm_log("Initializing WAMR runtime");

    /* Save configuration */
    if (config) {
        g_runtime.config = *config;
    } else {
        g_runtime.config.stack_size = 128 * 1024;
        g_runtime.config.heap_size = 16 * 1024 * 1024;
        g_runtime.config.shared_buffer_size = 64 * 1024 * 1024;
        g_runtime.config.enable_wasi = true;
        g_runtime.config.enable_debug = false;
    }

    /* Configure WAMR initialization */
    RuntimeInitArgs init_args;
    memset(&init_args, 0, sizeof(init_args));
    init_args.mem_alloc_type = Alloc_With_System_Allocator;

    /* Select running mode */
    switch (g_runtime.exec_mode) {
        case E9_WASM_MODE_FAST_JIT:
            wasm_log("Execution mode: Fast JIT");
            init_args.running_mode = Mode_Fast_JIT;
            break;
        case E9_WASM_MODE_AOT:
            wasm_log("Execution mode: AOT");
            init_args.running_mode = Mode_LLVM_AOT;
            break;
        case E9_WASM_MODE_INTERP:
        default:
            wasm_log("Execution mode: Fast Interpreter");
            init_args.running_mode = Mode_Fast_Interp;
            break;
    }

    /* Initialize WAMR */
    if (!wasm_runtime_full_init(&init_args)) {
        wasm_log("Failed to initialize WAMR");
        return -1;
    }

    /* Register native functions */
    if (!wasm_runtime_register_natives("env",
                                        g_native_symbols,
                                        sizeof(g_native_symbols) / sizeof(NativeSymbol))) {
        wasm_log("Failed to register native symbols");
        wasm_runtime_destroy();
        return -1;
    }

    /* Allocate shared buffer */
    size_t buf_size = g_runtime.config.shared_buffer_size;
    g_runtime.shared_buffer = mmap(NULL, buf_size,
                                    PROT_READ | PROT_WRITE,
                                    MAP_PRIVATE | MAP_ANONYMOUS,
                                    -1, 0);
    if (g_runtime.shared_buffer == MAP_FAILED) {
        wasm_log("Failed to allocate shared buffer: %s", strerror(errno));
        wasm_runtime_destroy();
        return -1;
    }
    g_runtime.shared_buffer_size = buf_size;

    /* Get executable path */
#ifdef __COSMOPOLITAN__
    const char *exe = GetProgramExecutableName();
    if (exe) {
        E9_STRCPY_SAFE(g_runtime.exe_path, sizeof(g_runtime.exe_path), exe);
    }
#else
    ssize_t len = readlink("/proc/self/exe", g_runtime.exe_path,
                           sizeof(g_runtime.exe_path) - 1);
    if (len > 0) {
        g_runtime.exe_path[len] = '\0';
    }
#endif

    g_runtime.initialized = true;
    wasm_log("WAMR initialized, shared buffer: %zu MB",
             buf_size / (1024 * 1024));

    return 0;
}

void e9wasm_shutdown(void)
{
    if (!g_runtime.initialized)
        return;

    wasm_log("Shutting down WAMR");

    if (g_runtime.exec_env) {
        wasm_runtime_destroy_exec_env(g_runtime.exec_env);
        g_runtime.exec_env = NULL;
    }

    if (g_runtime.module_inst) {
        wasm_runtime_deinstantiate(g_runtime.module_inst);
        g_runtime.module_inst = NULL;
    }

    if (g_runtime.module) {
        wasm_runtime_unload(g_runtime.module);
        g_runtime.module = NULL;
    }

    wasm_runtime_destroy();

    if (g_runtime.shared_buffer && g_runtime.shared_buffer != MAP_FAILED) {
        munmap(g_runtime.shared_buffer, g_runtime.shared_buffer_size);
        g_runtime.shared_buffer = NULL;
    }

    if (g_runtime.mapped_binary) {
        munmap(g_runtime.mapped_binary, g_runtime.mapped_size);
        if (g_runtime.mapped_fd >= 0)
            close(g_runtime.mapped_fd);
        g_runtime.mapped_binary = NULL;
    }

    g_runtime.initialized = false;
    wasm_log("WAMR shutdown complete");
}

/*
 * ============================================================================
 * Module loading
 * ============================================================================
 */

void *e9wasm_load_module(const char *path)
{
    if (!g_runtime.initialized) {
        wasm_log("Runtime not initialized");
        return NULL;
    }

    wasm_log("Loading module: %s", path);

    /* Read WASM bytes */
    uint8_t *wasm_bytes = NULL;
    size_t size = 0;

    /* Check if this is a ZipOS path */
    bool is_zipos_path = (strncmp(path, "/zip/", 5) == 0);

    /* For ZipOS paths, first check if the file exists to avoid crash */
    if (is_zipos_path) {
        if (zipos_is_disabled()) {
            wasm_log("Note: ZipOS disabled, %s not available", path);
            wasm_log("Running in native mode (no WASM patching engine)");
            return NULL;
        }
        if (!e9wasm_zipos_file_exists(path)) {
            wasm_log("Note: %s not found in ZipOS, running in native mode", path);
            return NULL;
        }
    }

    /* Try ZipOS first for /zip/ paths */
    if (is_zipos_path) {
        wasm_bytes = e9wasm_zipos_read(path, &size);
    }

    if (!wasm_bytes) {
        /* Try filesystem (for non-ZipOS paths or as fallback) */
        const char *fs_path = path;
        
        /* Skip /zip/ prefix for filesystem lookup */
        if (is_zipos_path) {
            fs_path = path + 5;  /* Skip "/zip/" */
        }
        
        int fd = open(fs_path, O_RDONLY);
        if (fd < 0) {
            /* For ZipOS paths, we already logged the "native mode" message */
            if (!is_zipos_path) {
                wasm_log("Cannot open module: %s", strerror(errno));
            }
            return NULL;
        }

        struct stat st;
        fstat(fd, &st);
        size = st.st_size;

        wasm_bytes = malloc(size);
        if (!wasm_bytes) {
            close(fd);
            return NULL;
        }

        if (read(fd, wasm_bytes, size) != (ssize_t)size) {
            close(fd);
            free(wasm_bytes);
            return NULL;
        }
        close(fd);
    }

    /* Load module */
    char error_buf[256];
    g_runtime.module = wasm_runtime_load(wasm_bytes, size,
                                          error_buf, sizeof(error_buf));
    free(wasm_bytes);

    if (!g_runtime.module) {
        wasm_log("Failed to load module: %s", error_buf);
        return NULL;
    }

    /* Instantiate module */
    uint32_t stack_size = g_runtime.config.stack_size;
    uint32_t heap_size = g_runtime.config.heap_size;

    g_runtime.module_inst = wasm_runtime_instantiate(
        g_runtime.module, stack_size, heap_size, error_buf, sizeof(error_buf));

    if (!g_runtime.module_inst) {
        wasm_log("Failed to instantiate module: %s", error_buf);
        wasm_runtime_unload(g_runtime.module);
        g_runtime.module = NULL;
        return NULL;
    }

    /* Create execution environment */
    g_runtime.exec_env = wasm_runtime_create_exec_env(
        g_runtime.module_inst, stack_size);

    if (!g_runtime.exec_env) {
        wasm_log("Failed to create exec env");
        wasm_runtime_deinstantiate(g_runtime.module_inst);
        wasm_runtime_unload(g_runtime.module);
        g_runtime.module_inst = NULL;
        g_runtime.module = NULL;
        return NULL;
    }

    wasm_log("Module loaded and instantiated");
    return (void *)g_runtime.module_inst;
}

int e9wasm_call(void *module, const char *func_name, int argc, const char *argv[])
{
    (void)module;

    if (!g_runtime.exec_env) {
        wasm_log("No execution environment");
        return -1;
    }

    wasm_function_inst_t func = wasm_runtime_lookup_function(
        g_runtime.module_inst, func_name);

    if (!func) {
        wasm_log("Function not found: %s", func_name);
        return -1;
    }

    /* Parse arguments as integers */
    uint32_t wasm_argc = 0;
    uint32_t wasm_argv[8] = {0};

    for (int i = 0; i < argc && i < 8; i++) {
        wasm_argv[i] = (uint32_t)atoi(argv[i]);
        wasm_argc++;
    }

    if (!wasm_runtime_call_wasm(g_runtime.exec_env, func, wasm_argc, wasm_argv)) {
        const char *exception = wasm_runtime_get_exception(g_runtime.module_inst);
        wasm_log("Call failed: %s", exception ? exception : "unknown");
        return -1;
    }

    return 0;
}

/*
 * ============================================================================
 * Shared buffer operations
 * ============================================================================
 */

uint8_t *e9wasm_get_shared_buffer(size_t *out_size)
{
    if (out_size)
        *out_size = g_runtime.shared_buffer_size;
    return g_runtime.shared_buffer;
}

size_t e9wasm_load_binary(const char *zip_path)
{
    if (!g_runtime.shared_buffer) {
        wasm_log("Shared buffer not allocated");
        return 0;
    }

    /* Construct full path */
    char full_path[512];
    if (zip_path[0] == '/') {
        E9_STRCPY_SAFE(full_path, sizeof(full_path), zip_path);
    } else {
        snprintf(full_path, sizeof(full_path), "/zip/%s", zip_path);
    }

    wasm_log("Loading binary: %s", full_path);

    int fd = open(full_path, O_RDONLY);
    if (fd < 0) {
        wasm_log("Failed to open: %s", strerror(errno));
        return 0;
    }

    struct stat st;
    fstat(fd, &st);
    size_t size = st.st_size;

    if (size > g_runtime.shared_buffer_size) {
        wasm_log("Binary too large: %zu > %zu", size, g_runtime.shared_buffer_size);
        close(fd);
        return 0;
    }

    ssize_t n = read(fd, g_runtime.shared_buffer, size);
    close(fd);

    if (n != (ssize_t)size) {
        wasm_log("Read error: %zd != %zu", n, size);
        return 0;
    }

    wasm_log("Loaded %zu bytes", size);
    return size;
}

/*
 * ============================================================================
 * Memory mapping
 * ============================================================================
 */

void *e9wasm_mmap_binary(const char *zip_path, size_t *out_size, bool writable)
{
    char full_path[512];
    if (zip_path[0] == '/') {
        E9_STRCPY_SAFE(full_path, sizeof(full_path), zip_path);
    } else {
        snprintf(full_path, sizeof(full_path), "/zip/%s", zip_path);
    }

    wasm_log("mmap binary: %s (writable=%d)", full_path, writable);

    /* Unmap previous */
    if (g_runtime.mapped_binary) {
        munmap(g_runtime.mapped_binary, g_runtime.mapped_size);
        close(g_runtime.mapped_fd);
        g_runtime.mapped_binary = NULL;
    }

    g_runtime.mapped_fd = open(full_path, O_RDONLY);
    if (g_runtime.mapped_fd < 0) {
        wasm_log("Failed to open: %s", strerror(errno));
        return NULL;
    }

    struct stat st;
    fstat(g_runtime.mapped_fd, &st);
    g_runtime.mapped_size = st.st_size;

    int prot = PROT_READ | (writable ? PROT_WRITE : 0);
    g_runtime.mapped_binary = mmap(NULL, g_runtime.mapped_size,
                                   prot, MAP_PRIVATE,
                                   g_runtime.mapped_fd, 0);

    if (g_runtime.mapped_binary == MAP_FAILED) {
        wasm_log("mmap failed: %s", strerror(errno));
        close(g_runtime.mapped_fd);
        g_runtime.mapped_binary = NULL;
        return NULL;
    }

    if (out_size)
        *out_size = g_runtime.mapped_size;

    wasm_log("mmap'd %zu bytes at %p", g_runtime.mapped_size, g_runtime.mapped_binary);
    return g_runtime.mapped_binary;
}

void e9wasm_munmap_binary(void *addr, size_t size)
{
    if (addr == g_runtime.mapped_binary) {
        munmap(g_runtime.mapped_binary, g_runtime.mapped_size);
        close(g_runtime.mapped_fd);
        g_runtime.mapped_binary = NULL;
        g_runtime.mapped_size = 0;
        g_runtime.mapped_fd = -1;
    } else if (addr) {
        munmap(addr, size);
    }
}

int e9wasm_apply_patch(void *mapped, size_t offset, const uint8_t *data, size_t size)
{
    if (!mapped || !data)
        return -1;

    memcpy((uint8_t *)mapped + offset, data, size);
    return 0;
}

void e9wasm_flush_icache(void *addr, size_t size)
{
#if defined(__aarch64__) || defined(_M_ARM64)
    __builtin___clear_cache(addr, (char *)addr + size);
#else
    /* x86-64: icache coherent with dcache */
    (void)addr;
    (void)size;
#endif
}

/*
 * ============================================================================
 * Event handling
 * ============================================================================
 */

void e9wasm_set_event_callback(E9WasmEventCallback callback, void *userdata)
{
    g_runtime.event_callback = callback;
    g_runtime.event_userdata = userdata;
}

/*
 * ============================================================================
 * ZipOS operations
 * ============================================================================
 */

const char *e9wasm_get_exe_path(void)
{
    return g_runtime.exe_path;
}

/*
 * Check if ZipOS is disabled via environment variable
 * Returns 1 if disabled, 0 otherwise
 */
static int zipos_is_disabled(void)
{
    const char *env = getenv("COSMOPOLITAN_DISABLE_ZIPOS");
    if (env && (strcmp(env, "1") == 0 || strcmp(env, "true") == 0)) {
        return 1;
    }
    return 0;
}

int e9wasm_zipos_available(void)
{
    /* Check if ZipOS is explicitly disabled */
    if (zipos_is_disabled()) {
        return 0;
    }

    /* Check if /zip/ is accessible */
    struct stat st;
    return (stat("/zip", &st) == 0) ? 1 : 0;
}

/*
 * Check if a file exists in ZipOS (safe check that doesn't crash)
 * Returns 1 if exists, 0 otherwise
 */
int e9wasm_zipos_file_exists(const char *name)
{
    if (zipos_is_disabled()) {
        return 0;
    }

    char full_path[512];
    if (name[0] == '/') {
        E9_STRCPY_SAFE(full_path, sizeof(full_path), name);
    } else {
        snprintf(full_path, sizeof(full_path), "/zip/%s", name);
    }

    struct stat st;
    return (stat(full_path, &st) == 0) ? 1 : 0;
}

uint8_t *e9wasm_zipos_read(const char *name, size_t *out_size)
{
    /* Check if ZipOS is disabled */
    if (zipos_is_disabled()) {
        return NULL;
    }

    char full_path[512];

    if (name[0] == '/') {
        E9_STRCPY_SAFE(full_path, sizeof(full_path), name);
    } else {
        snprintf(full_path, sizeof(full_path), "/zip/%s", name);
    }

    /* First check if file exists to avoid potential crash on non-existent files */
    struct stat st;
    if (stat(full_path, &st) < 0) {
        return NULL;
    }

    int fd = open(full_path, O_RDONLY);
    if (fd < 0) {
        return NULL;
    }

    if (fstat(fd, &st) < 0) {
        close(fd);
        return NULL;
    }

    size_t size = st.st_size;
    uint8_t *data = malloc(size);
    if (!data) {
        close(fd);
        return NULL;
    }

    if (read(fd, data, size) != (ssize_t)size) {
        free(data);
        close(fd);
        return NULL;
    }

    close(fd);

    if (out_size)
        *out_size = size;

    return data;
}

int e9wasm_zipos_append(const char *name, const uint8_t *data, size_t size)
{
    if (!g_runtime.exe_path[0]) {
        wasm_log("Executable path not available");
        return -1;
    }

    /* Open executable for appending */
    int fd = open(g_runtime.exe_path, O_RDWR | O_APPEND);
    if (fd < 0) {
        wasm_log("Cannot open exe for writing: %s", strerror(errno));
        return -1;
    }

    /*
     * ZIP Local File Header format
     */
    size_t name_len = strlen(name);

    uint8_t header[30];
    memset(header, 0, sizeof(header));

    /* Signature */
    header[0] = 0x50; header[1] = 0x4b; header[2] = 0x03; header[3] = 0x04;

    /* Version needed (2.0) */
    header[4] = 20; header[5] = 0;

    /* Compression: STORE (0) */
    header[8] = 0; header[9] = 0;

    /* Sizes */
    uint32_t size32 = (uint32_t)size;
    memcpy(&header[18], &size32, 4);  /* compressed */
    memcpy(&header[22], &size32, 4);  /* uncompressed */

    /* Filename length */
    uint16_t name_len16 = (uint16_t)name_len;
    memcpy(&header[26], &name_len16, 2);

    /* Write with error checking */
    if (write(fd, header, sizeof(header)) != (ssize_t)sizeof(header)) {
        close(fd);
        wasm_log("Failed to write ZIP header: %s", strerror(errno));
        return -1;
    }

    if (write(fd, name, name_len) != (ssize_t)name_len) {
        close(fd);
        wasm_log("Failed to write ZIP filename: %s", strerror(errno));
        return -1;
    }

    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        wasm_log("Failed to write ZIP data: %s", strerror(errno));
        return -1;
    }

    close(fd);
    wasm_log("Appended %zu bytes as %s", size, name);
    return 0;
}

int e9wasm_zipos_list(E9WasmZipCallback callback, void *userdata)
{
    (void)callback;
    (void)userdata;

    /* TODO: Implement ZIP directory parsing */
    wasm_log("zipos_list not yet implemented");
    return -1;
}

/*
 * ============================================================================
 * TUI functions (stubs)
 * ============================================================================
 */

int e9wasm_tui_init(void) { return 0; }
void e9wasm_tui_shutdown(void) {}
void e9wasm_tui_refresh(void) {}
int e9wasm_tui_get_key(void) { return -1; }
void e9wasm_tui_print(int row, int col, const char *text)
{
    (void)row; (void)col; (void)text;
}
void e9wasm_tui_clear(void) {}

/*
 * ============================================================================
 * File watching (stub)
 * ============================================================================
 */

int e9wasm_watch_file(const char *path, E9WasmFileCallback callback, void *userdata)
{
    (void)path;
    (void)callback;
    (void)userdata;
    wasm_log("File watching not yet implemented");
    return -1;
}
