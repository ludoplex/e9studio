/*
 * e9cosmo.h
 * Cosmopolitan Libc integration for e9patch
 *
 * Provides:
 * - APE (Actually Portable Executable) support
 * - hermit syscall emulation layer
 * - wasm3 interpreter bridge for Chrome/browser execution
 *
 * References:
 * - https://github.com/jart/cosmopolitan
 * - https://github.com/jart/cosmopolitan/tree/master/third_party/wasm3
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

#ifndef E9COSMO_H
#define E9COSMO_H

#include "e9platform.h"

#if defined(__COSMOPOLITAN__) || defined(E9_COSMO_ENABLED)

#include <cstdint>
#include <cstddef>

namespace e9cosmo {

/*
 * Cosmopolitan build modes
 */
enum class BuildMode {
    APE_NATIVE,      // Native APE binary (runs on Linux/macOS/Windows/BSD)
    APE_ASSIMILATE,  // Assimilated to native format
    WASM3_HOST,      // Host with embedded wasm3 interpreter
    WASM3_GUEST      // WASM module to run inside wasm3
};

/*
 * Get current build mode
 */
BuildMode getBuildMode();

/*
 * WASM3 interpreter bridge for running e9patch core in browser
 */
namespace wasm3 {

/*
 * WASM module handle
 */
struct Module;

/*
 * WASM runtime environment
 */
struct Runtime;

/*
 * Load WASM module from buffer
 */
Module *loadModule(const uint8_t *wasmBytes, size_t size);

/*
 * Create runtime environment
 */
Runtime *createRuntime(size_t stackSize = 64 * 1024);

/*
 * Link module to runtime
 */
bool linkModule(Runtime *rt, Module *mod);

/*
 * Call exported function
 */
int callFunction(Runtime *rt, const char *name, int argc, const char *argv[]);

/*
 * Get memory pointer for data exchange
 */
uint8_t *getMemory(Runtime *rt, size_t *outSize);

/*
 * Set memory region (for loading binary data)
 */
bool setMemoryRegion(Runtime *rt, uint32_t offset, const uint8_t *data, size_t size);

/*
 * Free resources
 */
void freeModule(Module *mod);
void freeRuntime(Runtime *rt);

/*
 * Host function registration (for callbacks to native code)
 */
using HostFunc = void* (*)(void *userData, int argc, const void *argv[]);

bool registerHostFunction(Runtime *rt, const char *moduleName,
                          const char *funcName, const char *signature,
                          HostFunc func, void *userData);

} // namespace wasm3

/*
 * Hermit syscall emulation support
 * Used when running as APE on different host OSes
 */
namespace hermit {

/*
 * Check if running under hermit emulation
 */
bool isEmulated();

/*
 * Get host operating system
 */
const char *getHostOS();

/*
 * Memory mapping abstraction that works across all hosts
 */
void *mapMemory(void *hint, size_t size, int prot, int flags);
bool unmapMemory(void *addr, size_t size);
bool protectMemory(void *addr, size_t size, int prot);

/*
 * File descriptor abstraction
 */
int openFile(const char *path, int flags, int mode);
int closeFile(int fd);
ssize_t readFile(int fd, void *buf, size_t count);
ssize_t writeFile(int fd, const void *buf, size_t count);
off_t seekFile(int fd, off_t offset, int whence);

/*
 * Process management (for e9tool -> e9patch communication)
 */
int forkProcess();
int execProcess(const char *path, char *const argv[], char *const envp[]);
int waitProcess(int pid, int *status, int options);

/*
 * Pipe for IPC
 */
int createPipe(int pipefd[2]);

} // namespace hermit

/*
 * IDE integration callbacks
 * These are called from JavaScript via wasm3 when running in browser
 */
namespace ide {

/*
 * Source file change notification
 */
struct SourceChange {
    const char *filePath;
    uint32_t lineStart;
    uint32_t lineEnd;
    uint32_t columnStart;
    uint32_t columnEnd;
    const char *newContent;
    size_t contentLength;
};

/*
 * Register callback for source changes from IDE
 */
using SourceChangeCallback = void (*)(const SourceChange *change, void *userData);
void registerSourceChangeCallback(SourceChangeCallback cb, void *userData);

/*
 * Patch result to send back to IDE
 */
struct PatchResult {
    intptr_t address;
    size_t originalSize;
    size_t patchedSize;
    const uint8_t *patchData;
    const char *functionName;
    const char *sourceFile;
    uint32_t sourceLine;
    bool success;
    const char *errorMessage;
};

/*
 * Register callback for patch results
 */
using PatchResultCallback = void (*)(const PatchResult *result, void *userData);
void registerPatchResultCallback(PatchResultCallback cb, void *userData);

/*
 * Debug breakpoint info
 */
struct BreakpointInfo {
    intptr_t address;
    const char *sourceFile;
    uint32_t sourceLine;
    const char *condition;
    bool enabled;
};

/*
 * Register callback for breakpoint hit
 */
using BreakpointCallback = void (*)(const BreakpointInfo *bp, void *userData);
void registerBreakpointCallback(BreakpointCallback cb, void *userData);

/*
 * Set breakpoint at source location
 */
bool setBreakpoint(const char *sourceFile, uint32_t line, const char *condition);

/*
 * Remove breakpoint
 */
bool removeBreakpoint(const char *sourceFile, uint32_t line);

/*
 * Request recompilation and hot-reload
 */
bool requestHotReload(const char *sourceFile);

} // namespace ide

/*
 * Chrome DevTools Protocol integration
 * For connecting to Chrome debugging
 */
namespace cdp {

/*
 * Connect to Chrome DevTools
 */
bool connect(const char *wsUrl);

/*
 * Disconnect from Chrome DevTools
 */
void disconnect();

/*
 * Check if connected
 */
bool isConnected();

/*
 * Send CDP command
 */
bool sendCommand(const char *method, const char *params);

/*
 * Register event handler
 */
using EventHandler = void (*)(const char *method, const char *params, void *userData);
void registerEventHandler(EventHandler handler, void *userData);

} // namespace cdp

} // namespace e9cosmo

/*
 * Exported C API for WASM/JavaScript interop
 */
#ifdef __cplusplus
extern "C" {
#endif

/*
 * Initialize e9patch in WASM/Cosmopolitan mode
 */
void e9cosmo_init(void);

/*
 * Process a source file change from IDE
 */
int e9cosmo_on_source_change(
    const char *filePath,
    uint32_t lineStart,
    uint32_t lineEnd,
    const char *newContent,
    size_t contentLength
);

/*
 * Load binary for patching
 */
int e9cosmo_load_binary(const uint8_t *data, size_t size, const char *name);

/*
 * Apply patch at address
 */
int e9cosmo_apply_patch(
    intptr_t address,
    const uint8_t *trampolineData,
    size_t trampolineSize
);

/*
 * Get patched binary
 */
int e9cosmo_get_patched_binary(uint8_t **outData, size_t *outSize);

/*
 * Free patched binary
 */
void e9cosmo_free_patched_binary(uint8_t *data);

/*
 * Set debug breakpoint
 */
int e9cosmo_set_breakpoint(intptr_t address);

/*
 * Clear debug breakpoint
 */
int e9cosmo_clear_breakpoint(intptr_t address);

/*
 * Request hot reload
 */
int e9cosmo_hot_reload(const char *sourceFile);

/*
 * Get version string
 */
const char *e9cosmo_get_version(void);

#ifdef __cplusplus
}
#endif

#endif /* __COSMOPOLITAN__ || E9_COSMO_ENABLED */

#endif /* E9COSMO_H */
