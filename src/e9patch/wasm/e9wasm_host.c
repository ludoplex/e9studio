/*
 * e9wasm_host.c
 * Embedded WASM VM Host Implementation
 *
 * Uses wasm3 interpreter with direct ZipOS integration.
 * Provides host functions for binary manipulation.
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

#include "e9wasm_host.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#ifdef __COSMOPOLITAN__
#include "libc/runtime/runtime.h"
#include "libc/calls/calls.h"
#include "libc/sysv/consts/map.h"
#include "libc/sysv/consts/prot.h"
#include "libc/sysv/consts/o.h"
#endif

/* wasm3 headers - from Cosmopolitan third_party or standalone */
#ifdef E9_WASM3_ENABLED
#include "wasm3.h"
#include "m3_env.h"
#endif

/*
 * Runtime state
 */
static struct {
    bool initialized;

#ifdef E9_WASM3_ENABLED
    IM3Environment env;
    IM3Runtime runtime;
    IM3Module module;
#endif

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

} g_runtime = {0};

/*
 * Logging
 */
static void wasm_log(const char *fmt, ...) {
    if (!g_runtime.config.enable_debug) return;

    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "[e9wasm] ");
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
}

#ifdef E9_WASM3_ENABLED

/*
 * Host function: log message from WASM
 */
static m3ApiRawFunction(host_log) {
    m3ApiGetArgMem(const char *, msg);
    m3ApiGetArg(uint32_t, len);

    char buf[1024];
    size_t copy_len = len < sizeof(buf) - 1 ? len : sizeof(buf) - 1;
    memcpy(buf, msg, copy_len);
    buf[copy_len] = '\0';

    fprintf(stderr, "[wasm] %s\n", buf);

    m3ApiSuccess();
}

/*
 * Host function: get shared buffer pointer (as WASM linear memory offset)
 */
static m3ApiRawFunction(host_get_shared_buffer) {
    m3ApiReturnType(uint32_t);

    /* Return offset in WASM linear memory where shared buffer starts */
    /* For wasm3, we need to place the shared buffer within WASM memory */
    /* This is a simplified approach - real impl would use proper memory management */

    uint32_t offset = 1024 * 1024;  /* 1MB offset */
    m3ApiReturn(offset);
}

/*
 * Host function: get shared buffer size
 */
static m3ApiRawFunction(host_get_shared_buffer_size) {
    m3ApiReturnType(uint32_t);
    m3ApiReturn((uint32_t)g_runtime.shared_buffer_size);
}

/*
 * Host function: load binary from ZipOS into shared buffer
 */
static m3ApiRawFunction(host_load_binary) {
    m3ApiReturnType(uint32_t);
    m3ApiGetArgMem(const char *, path);
    m3ApiGetArg(uint32_t, path_len);

    /* Construct full ZipOS path */
    char full_path[512];
    if (path_len > sizeof(full_path) - 10) {
        m3ApiReturn(0);
    }

    /* If path doesn't start with /zip/, prepend it */
    if (path_len >= 5 && memcmp(path, "/zip/", 5) == 0) {
        memcpy(full_path, path, path_len);
        full_path[path_len] = '\0';
    } else {
        snprintf(full_path, sizeof(full_path), "/zip/%.*s", path_len, path);
    }

    wasm_log("Loading binary: %s", full_path);

    /* Open from ZipOS */
    int fd = open(full_path, O_RDONLY);
    if (fd < 0) {
        wasm_log("Failed to open %s: %s", full_path, strerror(errno));
        m3ApiReturn(0);
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        m3ApiReturn(0);
    }

    size_t size = (size_t)st.st_size;
    if (size > g_runtime.shared_buffer_size) {
        wasm_log("Binary too large: %zu > %zu", size, g_runtime.shared_buffer_size);
        close(fd);
        m3ApiReturn(0);
    }

    /* Read into shared buffer */
    ssize_t n = read(fd, g_runtime.shared_buffer, size);
    close(fd);

    if (n != (ssize_t)size) {
        wasm_log("Read failed: %zd != %zu", n, size);
        m3ApiReturn(0);
    }

    wasm_log("Loaded %zu bytes", size);
    m3ApiReturn((uint32_t)size);
}

/*
 * Host function: mmap binary from ZipOS (zero-copy)
 */
static m3ApiRawFunction(host_mmap_binary) {
    m3ApiReturnType(uint32_t);
    m3ApiGetArgMem(const char *, path);
    m3ApiGetArg(uint32_t, path_len);
    m3ApiGetArg(uint32_t, writable);

    char full_path[512];
    snprintf(full_path, sizeof(full_path), "/zip/%.*s", path_len, path);

    wasm_log("mmap binary: %s (writable=%d)", full_path, writable);

    /* Unmap previous if any */
    if (g_runtime.mapped_binary) {
        munmap(g_runtime.mapped_binary, g_runtime.mapped_size);
        close(g_runtime.mapped_fd);
        g_runtime.mapped_binary = NULL;
    }

    /* Open */
    g_runtime.mapped_fd = open(full_path, O_RDONLY);
    if (g_runtime.mapped_fd < 0) {
        wasm_log("Failed to open for mmap: %s", strerror(errno));
        m3ApiReturn(0);
    }

    struct stat st;
    fstat(g_runtime.mapped_fd, &st);
    g_runtime.mapped_size = (size_t)st.st_size;

    /* mmap with MAP_PRIVATE for copy-on-write */
    int prot = PROT_READ | (writable ? PROT_WRITE : 0);
    g_runtime.mapped_binary = mmap(NULL, g_runtime.mapped_size,
                                   prot, MAP_PRIVATE,
                                   g_runtime.mapped_fd, 0);

    if (g_runtime.mapped_binary == MAP_FAILED) {
        wasm_log("mmap failed: %s", strerror(errno));
        close(g_runtime.mapped_fd);
        g_runtime.mapped_binary = NULL;
        m3ApiReturn(0);
    }

    wasm_log("mmap'd %zu bytes at %p", g_runtime.mapped_size, g_runtime.mapped_binary);

    /* Copy to shared buffer for WASM access */
    if (g_runtime.mapped_size <= g_runtime.shared_buffer_size) {
        memcpy(g_runtime.shared_buffer, g_runtime.mapped_binary, g_runtime.mapped_size);
    }

    m3ApiReturn((uint32_t)g_runtime.mapped_size);
}

/*
 * Host function: apply patch to mapped binary
 */
static m3ApiRawFunction(host_apply_patch) {
    m3ApiReturnType(int32_t);
    m3ApiGetArg(uint32_t, offset);
    m3ApiGetArgMem(const uint8_t *, data);
    m3ApiGetArg(uint32_t, size);

    if (!g_runtime.mapped_binary) {
        wasm_log("No binary mapped");
        m3ApiReturn(-1);
    }

    if (offset + size > g_runtime.mapped_size) {
        wasm_log("Patch out of bounds: %u + %u > %zu", offset, size, g_runtime.mapped_size);
        m3ApiReturn(-1);
    }

    wasm_log("Applying patch at offset 0x%x, size %u", offset, size);

    /* Ensure page is writable (COW will trigger) */
    void *page = (void *)((uintptr_t)(g_runtime.mapped_binary + offset) & ~0xFFF);
    size_t page_size = 4096;

    if (mprotect(page, page_size, PROT_READ | PROT_WRITE) < 0) {
        wasm_log("mprotect failed: %s", strerror(errno));
        m3ApiReturn(-1);
    }

    /* Write patch bytes */
    memcpy((uint8_t *)g_runtime.mapped_binary + offset, data, size);

    /* Make executable again if needed */
    mprotect(page, page_size, PROT_READ | PROT_EXEC);

    /* Update shared buffer copy */
    if (offset + size <= g_runtime.shared_buffer_size) {
        memcpy(g_runtime.shared_buffer + offset, data, size);
    }

    wasm_log("Patch applied successfully");
    m3ApiReturn(0);
}

/*
 * Host function: flush instruction cache
 */
static m3ApiRawFunction(host_flush_icache) {
    m3ApiGetArg(uint32_t, offset);
    m3ApiGetArg(uint32_t, size);

    if (g_runtime.mapped_binary) {
        void *addr = (uint8_t *)g_runtime.mapped_binary + offset;

        #ifdef __GNUC__
        __builtin___clear_cache(addr, (char *)addr + size);
        #endif
    }

    m3ApiSuccess();
}

/*
 * Host function: save patched binary to ZipOS
 */
static m3ApiRawFunction(host_save_to_zipos) {
    m3ApiReturnType(int32_t);
    m3ApiGetArgMem(const char *, name);
    m3ApiGetArg(uint32_t, name_len);
    m3ApiGetArg(uint32_t, size);

    if (!g_runtime.mapped_binary || size > g_runtime.mapped_size) {
        m3ApiReturn(-1);
    }

    char filename[256];
    snprintf(filename, sizeof(filename), "%.*s", name_len, name);

    int result = e9wasm_zipos_append(filename, g_runtime.mapped_binary, size);
    m3ApiReturn(result);
}

/*
 * Host function: notify host of event
 */
static m3ApiRawFunction(host_notify) {
    m3ApiGetArgMem(const char *, event);
    m3ApiGetArg(uint32_t, event_len);
    m3ApiGetArgMem(const char *, data);
    m3ApiGetArg(uint32_t, data_len);

    if (g_runtime.event_callback) {
        char event_buf[256], data_buf[4096];

        snprintf(event_buf, sizeof(event_buf), "%.*s", event_len, event);
        snprintf(data_buf, sizeof(data_buf), "%.*s", data_len, data);

        g_runtime.event_callback(event_buf, data_buf, g_runtime.event_userdata);
    }

    m3ApiSuccess();
}

/*
 * Link host functions to WASM module
 */
static int link_host_functions(IM3Module module) {
    M3Result result;

    #define LINK(name, sig) \
        result = m3_LinkRawFunction(module, "env", #name, sig, &name); \
        if (result) { wasm_log("Failed to link " #name ": %s", result); return -1; }

    LINK(host_log, "v(ii)");
    LINK(host_get_shared_buffer, "i()");
    LINK(host_get_shared_buffer_size, "i()");
    LINK(host_load_binary, "i(ii)");
    LINK(host_mmap_binary, "i(iii)");
    LINK(host_apply_patch, "i(iii)");
    LINK(host_flush_icache, "v(ii)");
    LINK(host_save_to_zipos, "i(iii)");
    LINK(host_notify, "v(iiii)");

    #undef LINK

    return 0;
}

#endif /* E9_WASM3_ENABLED */

/*
 * Public API Implementation
 */

int e9wasm_init(const E9WasmConfig *config) {
    if (g_runtime.initialized) {
        return 0;
    }

    /* Store config */
    if (config) {
        g_runtime.config = *config;
    } else {
        /* Defaults */
        g_runtime.config.stack_size = 64 * 1024;           /* 64KB */
        g_runtime.config.heap_size = 16 * 1024 * 1024;     /* 16MB */
        g_runtime.config.shared_buffer_size = 64 * 1024 * 1024; /* 64MB */
        g_runtime.config.enable_wasi = true;
        g_runtime.config.enable_debug = false;
        g_runtime.config.module_path = "/zip/e9patch.wasm";
    }

    wasm_log("Initializing WASM runtime");

    /* Allocate shared buffer */
    g_runtime.shared_buffer = mmap(NULL, g_runtime.config.shared_buffer_size,
                                   PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (g_runtime.shared_buffer == MAP_FAILED) {
        fprintf(stderr, "Failed to allocate shared buffer: %s\n", strerror(errno));
        return -1;
    }
    g_runtime.shared_buffer_size = g_runtime.config.shared_buffer_size;

    /* Get executable path */
    #ifdef __linux__
    ssize_t len = readlink("/proc/self/exe", g_runtime.exe_path,
                           sizeof(g_runtime.exe_path) - 1);
    if (len > 0) g_runtime.exe_path[len] = '\0';
    #elif defined(__APPLE__)
    uint32_t size = sizeof(g_runtime.exe_path);
    _NSGetExecutablePath(g_runtime.exe_path, &size);
    #endif

#ifdef E9_WASM3_ENABLED
    /* Create wasm3 environment */
    g_runtime.env = m3_NewEnvironment();
    if (!g_runtime.env) {
        fprintf(stderr, "Failed to create wasm3 environment\n");
        return -1;
    }

    /* Create runtime */
    g_runtime.runtime = m3_NewRuntime(g_runtime.env,
                                       g_runtime.config.stack_size,
                                       NULL);
    if (!g_runtime.runtime) {
        fprintf(stderr, "Failed to create wasm3 runtime\n");
        m3_FreeEnvironment(g_runtime.env);
        return -1;
    }

    wasm_log("wasm3 runtime created");
#else
    wasm_log("wasm3 not enabled, running in stub mode");
#endif

    g_runtime.initialized = true;
    return 0;
}

void e9wasm_shutdown(void) {
    if (!g_runtime.initialized) return;

#ifdef E9_WASM3_ENABLED
    if (g_runtime.runtime) {
        m3_FreeRuntime(g_runtime.runtime);
    }
    if (g_runtime.env) {
        m3_FreeEnvironment(g_runtime.env);
    }
#endif

    if (g_runtime.mapped_binary) {
        munmap(g_runtime.mapped_binary, g_runtime.mapped_size);
        close(g_runtime.mapped_fd);
    }

    if (g_runtime.shared_buffer) {
        munmap(g_runtime.shared_buffer, g_runtime.shared_buffer_size);
    }

    memset(&g_runtime, 0, sizeof(g_runtime));
}

void *e9wasm_load_module(const char *path) {
#ifdef E9_WASM3_ENABLED
    if (!g_runtime.initialized) return NULL;

    wasm_log("Loading module: %s", path);

    /* Read WASM file from ZipOS */
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        wasm_log("Failed to open %s: %s", path, strerror(errno));
        return NULL;
    }

    struct stat st;
    fstat(fd, &st);
    size_t size = (size_t)st.st_size;

    uint8_t *wasm_bytes = malloc(size);
    if (!wasm_bytes) {
        close(fd);
        return NULL;
    }

    read(fd, wasm_bytes, size);
    close(fd);

    /* Parse module */
    M3Result result = m3_ParseModule(g_runtime.env, &g_runtime.module,
                                     wasm_bytes, size);
    free(wasm_bytes);

    if (result) {
        wasm_log("Failed to parse module: %s", result);
        return NULL;
    }

    /* Load into runtime */
    result = m3_LoadModule(g_runtime.runtime, g_runtime.module);
    if (result) {
        wasm_log("Failed to load module: %s", result);
        return NULL;
    }

    /* Link host functions */
    if (link_host_functions(g_runtime.module) < 0) {
        return NULL;
    }

    wasm_log("Module loaded and linked");
    return g_runtime.module;
#else
    (void)path;
    return NULL;
#endif
}

int e9wasm_call(void *module, const char *func_name, int argc, const char *argv[]) {
#ifdef E9_WASM3_ENABLED
    if (!module) return -1;

    IM3Function func;
    M3Result result = m3_FindFunction(&func, g_runtime.runtime, func_name);
    if (result) {
        wasm_log("Function not found: %s (%s)", func_name, result);
        return -1;
    }

    result = m3_CallArgv(func, argc, argv);
    if (result) {
        wasm_log("Call failed: %s", result);
        return -1;
    }

    return 0;
#else
    (void)module; (void)func_name; (void)argc; (void)argv;
    return -1;
#endif
}

uint8_t *e9wasm_get_shared_buffer(size_t *out_size) {
    if (out_size) *out_size = g_runtime.shared_buffer_size;
    return g_runtime.shared_buffer;
}

size_t e9wasm_load_binary(const char *zip_path) {
    char full_path[512];
    snprintf(full_path, sizeof(full_path), "/zip/%s", zip_path);

    int fd = open(full_path, O_RDONLY);
    if (fd < 0) return 0;

    struct stat st;
    fstat(fd, &st);
    size_t size = (size_t)st.st_size;

    if (size > g_runtime.shared_buffer_size) {
        close(fd);
        return 0;
    }

    ssize_t n = read(fd, g_runtime.shared_buffer, size);
    close(fd);

    return n > 0 ? (size_t)n : 0;
}

void *e9wasm_mmap_binary(const char *zip_path, size_t *out_size, bool writable) {
    char full_path[512];
    snprintf(full_path, sizeof(full_path), "/zip/%s", zip_path);

    int fd = open(full_path, O_RDONLY);
    if (fd < 0) return NULL;

    struct stat st;
    fstat(fd, &st);
    size_t size = (size_t)st.st_size;

    int prot = PROT_READ | (writable ? PROT_WRITE : 0);
    void *addr = mmap(NULL, size, prot, MAP_PRIVATE, fd, 0);

    if (addr == MAP_FAILED) {
        close(fd);
        return NULL;
    }

    /* Keep fd open for potential re-mapping */
    if (out_size) *out_size = size;
    return addr;
}

void e9wasm_munmap_binary(void *addr, size_t size) {
    if (addr) munmap(addr, size);
}

int e9wasm_apply_patch(void *mapped, size_t offset, const uint8_t *data, size_t size) {
    if (!mapped) return -1;

    /* Make page writable */
    void *page = (void *)((uintptr_t)((uint8_t *)mapped + offset) & ~0xFFF);
    if (mprotect(page, 4096, PROT_READ | PROT_WRITE) < 0) {
        return -1;
    }

    /* Write patch */
    memcpy((uint8_t *)mapped + offset, data, size);

    /* Restore execute permission */
    mprotect(page, 4096, PROT_READ | PROT_EXEC);

    return 0;
}

void e9wasm_flush_icache(void *addr, size_t size) {
#ifdef __GNUC__
    __builtin___clear_cache(addr, (char *)addr + size);
#else
    (void)addr; (void)size;
#endif
}

void e9wasm_set_event_callback(E9WasmEventCallback callback, void *userdata) {
    g_runtime.event_callback = callback;
    g_runtime.event_userdata = userdata;
}

int e9wasm_zipos_append(const char *name, const uint8_t *data, size_t size) {
    /* Open executable for appending */
    int fd = open(g_runtime.exe_path, O_RDWR | O_APPEND);
    if (fd < 0) {
        wasm_log("Cannot open exe for writing: %s", strerror(errno));
        return -1;
    }

    /*
     * ZIP Local File Header format:
     * 4 bytes: signature (0x04034b50)
     * 2 bytes: version needed (20 = 2.0)
     * 2 bytes: flags (0)
     * 2 bytes: compression (0 = STORE)
     * 2 bytes: mod time
     * 2 bytes: mod date
     * 4 bytes: CRC-32
     * 4 bytes: compressed size
     * 4 bytes: uncompressed size
     * 2 bytes: filename length
     * 2 bytes: extra field length (0)
     * n bytes: filename
     * m bytes: extra field
     * x bytes: file data
     */

    size_t name_len = strlen(name);

    uint8_t header[30];
    memset(header, 0, sizeof(header));

    /* Signature */
    header[0] = 0x50; header[1] = 0x4b; header[2] = 0x03; header[3] = 0x04;

    /* Version needed (2.0) */
    header[4] = 20; header[5] = 0;

    /* Flags, compression (STORE) */
    header[6] = 0; header[7] = 0;
    header[8] = 0; header[9] = 0;

    /* TODO: proper CRC calculation */
    uint32_t crc = 0;
    memcpy(&header[14], &crc, 4);

    /* Sizes */
    uint32_t size32 = (uint32_t)size;
    memcpy(&header[18], &size32, 4);  /* compressed */
    memcpy(&header[22], &size32, 4);  /* uncompressed */

    /* Filename length */
    uint16_t name_len16 = (uint16_t)name_len;
    memcpy(&header[26], &name_len16, 2);

    /* Extra field length (0) */
    header[28] = 0; header[29] = 0;

    /* Write header */
    write(fd, header, sizeof(header));

    /* Write filename */
    write(fd, name, name_len);

    /* Write data */
    write(fd, data, size);

    /* TODO: Update central directory and EOCD */
    /* This is a simplified implementation - full impl needs to:
     * 1. Read existing central directory
     * 2. Add new entry
     * 3. Write new central directory
     * 4. Write new EOCD
     */

    close(fd);

    wasm_log("Appended %zu bytes as %s", size, name);
    return 0;
}

int e9wasm_zipos_list(E9WasmZipCallback callback, void *userdata) {
    /* Simple approach: iterate /zip/ directory */
    /* Full implementation would parse ZIP central directory */

    /* For now, just try to open /zip/ as directory */
    /* Cosmopolitan provides this as a virtual directory */

    /* TODO: implement proper ZIP directory listing */
    (void)callback;
    (void)userdata;
    return 0;
}

const char *e9wasm_get_exe_path(void) {
    return g_runtime.exe_path;
}

/*
 * TUI implementation (minimal terminal UI)
 */
static bool g_tui_initialized = false;

int e9wasm_tui_init(void) {
    if (g_tui_initialized) return 0;

    /* Put terminal in raw mode */
    printf("\033[?1049h");  /* Alternate screen buffer */
    printf("\033[2J");      /* Clear screen */
    printf("\033[H");       /* Home cursor */
    fflush(stdout);

    g_tui_initialized = true;
    return 0;
}

void e9wasm_tui_shutdown(void) {
    if (!g_tui_initialized) return;

    printf("\033[?1049l");  /* Normal screen buffer */
    fflush(stdout);

    g_tui_initialized = false;
}

void e9wasm_tui_refresh(void) {
    fflush(stdout);
}

void e9wasm_tui_print(int row, int col, const char *text) {
    printf("\033[%d;%dH%s", row + 1, col + 1, text);
}

void e9wasm_tui_clear(void) {
    printf("\033[2J\033[H");
}
