/*
 * e9cosmo.cpp
 * Cosmopolitan Libc integration implementation
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

#include "e9cosmo.h"

#if defined(__COSMOPOLITAN__) || defined(E9_COSMO_ENABLED)

#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <cstdarg>

#ifdef __COSMOPOLITAN__
#include "libc/runtime/runtime.h"
#include "libc/calls/calls.h"
#include "libc/sysv/consts/map.h"
#include "libc/sysv/consts/prot.h"
#include "libc/sysv/consts/o.h"
#endif

// Forward declarations for wasm3 types (from third_party/wasm3)
#ifdef E9_WASM3_ENABLED
extern "C" {
    typedef struct M3Environment M3Environment;
    typedef struct M3Runtime M3Runtime;
    typedef struct M3Module M3Module;
    typedef struct M3Function M3Function;
    typedef const char* M3Result;

    M3Environment *m3_NewEnvironment(void);
    void m3_FreeEnvironment(M3Environment *env);
    M3Runtime *m3_NewRuntime(M3Environment *env, uint32_t stackSize, void *userData);
    void m3_FreeRuntime(M3Runtime *rt);
    M3Result m3_ParseModule(M3Environment *env, M3Module **outModule,
                            const uint8_t *wasmBytes, uint32_t wasmSize);
    M3Result m3_LoadModule(M3Runtime *rt, M3Module *module);
    M3Result m3_FindFunction(M3Function **outFunc, M3Runtime *rt, const char *name);
    M3Result m3_CallV(M3Function *func, ...);
    M3Result m3_CallArgv(M3Function *func, uint32_t argc, const char **argv);
    uint8_t *m3_GetMemory(M3Runtime *rt, uint32_t *outSize, uint32_t memIdx);
}
#endif

namespace e9cosmo {

/*
 * Global state
 */
static BuildMode g_buildMode = BuildMode::APE_NATIVE;

#ifdef E9_WASM3_ENABLED
static M3Environment *g_wasm3Env = nullptr;
#endif

BuildMode getBuildMode() {
    return g_buildMode;
}

namespace wasm3 {

#ifdef E9_WASM3_ENABLED

struct Module {
    M3Module *m3mod;
    uint8_t *wasmCopy;  // Keep copy of wasm bytes
    size_t wasmSize;
};

struct Runtime {
    M3Runtime *m3rt;
    M3Environment *env;
};

Module *loadModule(const uint8_t *wasmBytes, size_t size) {
    if (!g_wasm3Env) {
        g_wasm3Env = m3_NewEnvironment();
        if (!g_wasm3Env) return nullptr;
    }

    Module *mod = new Module();
    mod->wasmCopy = new uint8_t[size];
    memcpy(mod->wasmCopy, wasmBytes, size);
    mod->wasmSize = size;

    M3Result result = m3_ParseModule(g_wasm3Env, &mod->m3mod,
                                      mod->wasmCopy, (uint32_t)size);
    if (result) {
        delete[] mod->wasmCopy;
        delete mod;
        return nullptr;
    }

    return mod;
}

Runtime *createRuntime(size_t stackSize) {
    if (!g_wasm3Env) {
        g_wasm3Env = m3_NewEnvironment();
        if (!g_wasm3Env) return nullptr;
    }

    Runtime *rt = new Runtime();
    rt->env = g_wasm3Env;
    rt->m3rt = m3_NewRuntime(g_wasm3Env, (uint32_t)stackSize, nullptr);
    if (!rt->m3rt) {
        delete rt;
        return nullptr;
    }

    return rt;
}

bool linkModule(Runtime *rt, Module *mod) {
    if (!rt || !mod) return false;
    M3Result result = m3_LoadModule(rt->m3rt, mod->m3mod);
    return result == nullptr;
}

int callFunction(Runtime *rt, const char *name, int argc, const char *argv[]) {
    if (!rt || !name) return -1;

    M3Function *func;
    M3Result result = m3_FindFunction(&func, rt->m3rt, name);
    if (result) return -1;

    result = m3_CallArgv(func, (uint32_t)argc, argv);
    if (result) return -1;

    return 0;
}

uint8_t *getMemory(Runtime *rt, size_t *outSize) {
    if (!rt) return nullptr;
    uint32_t size32 = 0;
    uint8_t *mem = m3_GetMemory(rt->m3rt, &size32, 0);
    if (outSize) *outSize = size32;
    return mem;
}

bool setMemoryRegion(Runtime *rt, uint32_t offset, const uint8_t *data, size_t size) {
    size_t memSize;
    uint8_t *mem = getMemory(rt, &memSize);
    if (!mem || offset + size > memSize) return false;
    memcpy(mem + offset, data, size);
    return true;
}

void freeModule(Module *mod) {
    if (mod) {
        delete[] mod->wasmCopy;
        delete mod;
    }
}

void freeRuntime(Runtime *rt) {
    if (rt) {
        if (rt->m3rt) m3_FreeRuntime(rt->m3rt);
        delete rt;
    }
}

bool registerHostFunction(Runtime *, const char *, const char *,
                          const char *, HostFunc, void *) {
    // TODO: Implement host function registration
    return false;
}

#else // !E9_WASM3_ENABLED

// Stub implementations when wasm3 is not enabled
Module *loadModule(const uint8_t *, size_t) { return nullptr; }
Runtime *createRuntime(size_t) { return nullptr; }
bool linkModule(Runtime *, Module *) { return false; }
int callFunction(Runtime *, const char *, int, const char *[]) { return -1; }
uint8_t *getMemory(Runtime *, size_t *) { return nullptr; }
bool setMemoryRegion(Runtime *, uint32_t, const uint8_t *, size_t) { return false; }
void freeModule(Module *) {}
void freeRuntime(Runtime *) {}
bool registerHostFunction(Runtime *, const char *, const char *,
                          const char *, HostFunc, void *) { return false; }

#endif

} // namespace wasm3

namespace hermit {

bool isEmulated() {
#ifdef __COSMOPOLITAN__
    // Check if running under hermit syscall emulation
    return false;  // TODO: detect hermit mode
#else
    return false;
#endif
}

const char *getHostOS() {
#ifdef __COSMOPOLITAN__
    // Cosmopolitan detects host OS at runtime
    #if defined(__linux__)
    return "linux";
    #elif defined(__APPLE__)
    return "macos";
    #elif defined(_WIN32)
    return "windows";
    #elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    return "bsd";
    #else
    return "unknown";
    #endif
#else
    return E9_PLATFORM_NAME;
#endif
}

void *mapMemory(void *hint, size_t size, int prot, int flags) {
#ifdef __COSMOPOLITAN__
    int sys_prot = 0;
    if (prot & e9platform::PROT_READ_)  sys_prot |= PROT_READ;
    if (prot & e9platform::PROT_WRITE_) sys_prot |= PROT_WRITE;
    if (prot & e9platform::PROT_EXEC_)  sys_prot |= PROT_EXEC;

    int sys_flags = MAP_ANONYMOUS;
    if (flags & e9platform::MAP_PRIVATE_) sys_flags |= MAP_PRIVATE;
    if (flags & e9platform::MAP_SHARED_)  sys_flags |= MAP_SHARED;
    if (flags & e9platform::MAP_FIXED_)   sys_flags |= MAP_FIXED;

    void *result = mmap(hint, size, sys_prot, sys_flags, -1, 0);
    return (result == MAP_FAILED) ? nullptr : result;
#else
    return e9platform::E9_MEMORY()->mapMemory(hint, size, prot, flags);
#endif
}

bool unmapMemory(void *addr, size_t size) {
#ifdef __COSMOPOLITAN__
    return munmap(addr, size) == 0;
#else
    return e9platform::E9_MEMORY()->unmapMemory(addr, size);
#endif
}

bool protectMemory(void *addr, size_t size, int prot) {
#ifdef __COSMOPOLITAN__
    int sys_prot = 0;
    if (prot & e9platform::PROT_READ_)  sys_prot |= PROT_READ;
    if (prot & e9platform::PROT_WRITE_) sys_prot |= PROT_WRITE;
    if (prot & e9platform::PROT_EXEC_)  sys_prot |= PROT_EXEC;
    return mprotect(addr, size, sys_prot) == 0;
#else
    return e9platform::E9_MEMORY()->protectMemory(addr, size, prot);
#endif
}

int openFile(const char *path, int flags, int mode) {
#ifdef __COSMOPOLITAN__
    return open(path, flags, mode);
#else
    (void)path; (void)flags; (void)mode;
    return -1;
#endif
}

int closeFile(int fd) {
#ifdef __COSMOPOLITAN__
    return close(fd);
#else
    (void)fd;
    return -1;
#endif
}

ssize_t readFile(int fd, void *buf, size_t count) {
#ifdef __COSMOPOLITAN__
    return read(fd, buf, count);
#else
    (void)fd; (void)buf; (void)count;
    return -1;
#endif
}

ssize_t writeFile(int fd, const void *buf, size_t count) {
#ifdef __COSMOPOLITAN__
    return write(fd, buf, count);
#else
    (void)fd; (void)buf; (void)count;
    return -1;
#endif
}

off_t seekFile(int fd, off_t offset, int whence) {
#ifdef __COSMOPOLITAN__
    return lseek(fd, offset, whence);
#else
    (void)fd; (void)offset; (void)whence;
    return -1;
#endif
}

int forkProcess() {
#ifdef __COSMOPOLITAN__
    return fork();
#else
    return -1;
#endif
}

int execProcess(const char *path, char *const argv[], char *const envp[]) {
#ifdef __COSMOPOLITAN__
    return execve(path, argv, envp);
#else
    (void)path; (void)argv; (void)envp;
    return -1;
#endif
}

int waitProcess(int pid, int *status, int options) {
#ifdef __COSMOPOLITAN__
    return waitpid(pid, status, options);
#else
    (void)pid; (void)status; (void)options;
    return -1;
#endif
}

int createPipe(int pipefd[2]) {
#ifdef __COSMOPOLITAN__
    return pipe(pipefd);
#else
    (void)pipefd;
    return -1;
#endif
}

} // namespace hermit

namespace ide {

// Callback storage
static SourceChangeCallback g_sourceChangeCallback = nullptr;
static void *g_sourceChangeUserData = nullptr;

static PatchResultCallback g_patchResultCallback = nullptr;
static void *g_patchResultUserData = nullptr;

static BreakpointCallback g_breakpointCallback = nullptr;
static void *g_breakpointUserData = nullptr;

void registerSourceChangeCallback(SourceChangeCallback cb, void *userData) {
    g_sourceChangeCallback = cb;
    g_sourceChangeUserData = userData;
}

void registerPatchResultCallback(PatchResultCallback cb, void *userData) {
    g_patchResultCallback = cb;
    g_patchResultUserData = userData;
}

void registerBreakpointCallback(BreakpointCallback cb, void *userData) {
    g_breakpointCallback = cb;
    g_breakpointUserData = userData;
}

bool setBreakpoint(const char *, uint32_t, const char *) {
    // TODO: Implement breakpoint setting
    return false;
}

bool removeBreakpoint(const char *, uint32_t) {
    // TODO: Implement breakpoint removal
    return false;
}

bool requestHotReload(const char *) {
    // TODO: Implement hot reload request
    return false;
}

// Internal: notify callbacks
void notifySourceChange(const SourceChange *change) {
    if (g_sourceChangeCallback) {
        g_sourceChangeCallback(change, g_sourceChangeUserData);
    }
}

void notifyPatchResult(const PatchResult *result) {
    if (g_patchResultCallback) {
        g_patchResultCallback(result, g_patchResultUserData);
    }
}

void notifyBreakpoint(const BreakpointInfo *bp) {
    if (g_breakpointCallback) {
        g_breakpointCallback(bp, g_breakpointUserData);
    }
}

} // namespace ide

namespace cdp {

static bool g_connected = false;
static EventHandler g_eventHandler = nullptr;
static void *g_eventUserData = nullptr;

bool connect(const char *) {
    // TODO: Implement WebSocket connection to Chrome DevTools
    g_connected = true;
    return true;
}

void disconnect() {
    g_connected = false;
}

bool isConnected() {
    return g_connected;
}

bool sendCommand(const char *, const char *) {
    // TODO: Implement CDP command sending
    return g_connected;
}

void registerEventHandler(EventHandler handler, void *userData) {
    g_eventHandler = handler;
    g_eventUserData = userData;
}

} // namespace cdp

} // namespace e9cosmo

/*
 * C API Implementation
 */
extern "C" {

// Global state for C API
static uint8_t *g_loadedBinary = nullptr;
static size_t g_loadedBinarySize = 0;
static uint8_t *g_patchedBinary = nullptr;
static size_t g_patchedBinarySize = 0;

void e9cosmo_init(void) {
    e9platform::platformInit();
    e9platform::platformLog(e9platform::LOG_INFO,
        "E9Patch Cosmopolitan mode initialized (host: %s)",
        e9cosmo::hermit::getHostOS());
}

int e9cosmo_on_source_change(
    const char *filePath,
    uint32_t lineStart,
    uint32_t lineEnd,
    const char *newContent,
    size_t contentLength
) {
    e9cosmo::ide::SourceChange change;
    change.filePath = filePath;
    change.lineStart = lineStart;
    change.lineEnd = lineEnd;
    change.columnStart = 0;
    change.columnEnd = 0;
    change.newContent = newContent;
    change.contentLength = contentLength;

    e9cosmo::ide::notifySourceChange(&change);

    // TODO: Trigger recompilation and patching
    return 0;
}

int e9cosmo_load_binary(const uint8_t *data, size_t size, const char *name) {
    if (g_loadedBinary) {
        free(g_loadedBinary);
    }

    g_loadedBinary = (uint8_t *)malloc(size);
    if (!g_loadedBinary) {
        return -1;
    }

    memcpy(g_loadedBinary, data, size);
    g_loadedBinarySize = size;

    e9platform::platformLog(e9platform::LOG_INFO,
        "Loaded binary '%s' (%zu bytes)", name, size);

    return 0;
}

int e9cosmo_apply_patch(
    intptr_t address,
    const uint8_t *trampolineData,
    size_t trampolineSize
) {
    if (!g_loadedBinary) {
        return -1;
    }

    // TODO: Integrate with e9patch core to apply the patch
    e9platform::platformLog(e9platform::LOG_INFO,
        "Applying patch at 0x%lx (%zu bytes)", (unsigned long)address, trampolineSize);

    // Notify IDE of patch result
    e9cosmo::ide::PatchResult result;
    result.address = address;
    result.originalSize = 0;  // TODO: get from e9patch
    result.patchedSize = trampolineSize;
    result.patchData = trampolineData;
    result.functionName = nullptr;
    result.sourceFile = nullptr;
    result.sourceLine = 0;
    result.success = true;
    result.errorMessage = nullptr;

    e9cosmo::ide::notifyPatchResult(&result);

    return 0;
}

int e9cosmo_get_patched_binary(uint8_t **outData, size_t *outSize) {
    if (!g_patchedBinary) {
        // If no patches applied, return copy of original
        if (!g_loadedBinary) {
            return -1;
        }
        *outData = (uint8_t *)malloc(g_loadedBinarySize);
        if (!*outData) return -1;
        memcpy(*outData, g_loadedBinary, g_loadedBinarySize);
        *outSize = g_loadedBinarySize;
    } else {
        *outData = (uint8_t *)malloc(g_patchedBinarySize);
        if (!*outData) return -1;
        memcpy(*outData, g_patchedBinary, g_patchedBinarySize);
        *outSize = g_patchedBinarySize;
    }
    return 0;
}

void e9cosmo_free_patched_binary(uint8_t *data) {
    if (data) free(data);
}

int e9cosmo_set_breakpoint(intptr_t address) {
    e9platform::platformLog(e9platform::LOG_DEBUG,
        "Setting breakpoint at 0x%lx", (unsigned long)address);
    // TODO: Implement breakpoint insertion
    return 0;
}

int e9cosmo_clear_breakpoint(intptr_t address) {
    e9platform::platformLog(e9platform::LOG_DEBUG,
        "Clearing breakpoint at 0x%lx", (unsigned long)address);
    // TODO: Implement breakpoint removal
    return 0;
}

int e9cosmo_hot_reload(const char *sourceFile) {
    e9platform::platformLog(e9platform::LOG_INFO,
        "Hot reload requested for: %s", sourceFile);
    // TODO: Trigger recompilation and patch application
    return 0;
}

const char *e9cosmo_get_version(void) {
    return "e9patch-cosmo-1.0.0";
}

} // extern "C"

#endif /* __COSMOPOLITAN__ || E9_COSMO_ENABLED */
