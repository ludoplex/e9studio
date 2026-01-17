/*
 * e9platform.h
 * Platform Abstraction Layer for e9patch
 *
 * Supports:
 * - Native Linux/POSIX
 * - Cosmopolitan Libc (portable binaries)
 * - WebAssembly (WASM) via Emscripten/WASI
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

#ifndef E9PLATFORM_H
#define E9PLATFORM_H

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <functional>

/*
 * Platform detection macros
 */
#if defined(__COSMOPOLITAN__)
    #define E9_PLATFORM_COSMOPOLITAN 1
    #define E9_PLATFORM_NAME "cosmopolitan"
#elif defined(__EMSCRIPTEN__) || defined(__wasm__) || defined(__wasm32__) || defined(__wasm64__)
    #define E9_PLATFORM_WASM 1
    #define E9_PLATFORM_NAME "wasm"
#elif defined(_WIN32) || defined(_WIN64)
    #define E9_PLATFORM_WINDOWS 1
    #define E9_PLATFORM_NAME "windows"
#elif defined(__linux__) || defined(__unix__) || defined(__APPLE__)
    #define E9_PLATFORM_POSIX 1
    #define E9_PLATFORM_NAME "posix"
#else
    #error "Unsupported platform"
#endif

/*
 * Feature availability
 */
#if defined(E9_PLATFORM_WASM)
    #define E9_HAS_MMAP         0
    #define E9_HAS_SIGNALS      0
    #define E9_HAS_FORK         0
    #define E9_HAS_SYSCALLS     0
    #define E9_HAS_FILE_IO      1  // Via WASI or JS bridge
    #define E9_HAS_TACTIC_B0    0  // No signal-based patching
#elif defined(E9_PLATFORM_COSMOPOLITAN)
    #define E9_HAS_MMAP         1
    #define E9_HAS_SIGNALS      1
    #define E9_HAS_FORK         1
    #define E9_HAS_SYSCALLS     1
    #define E9_HAS_FILE_IO      1
    #define E9_HAS_TACTIC_B0    1
#else
    #define E9_HAS_MMAP         1
    #define E9_HAS_SIGNALS      1
    #define E9_HAS_FORK         1
    #define E9_HAS_SYSCALLS     1
    #define E9_HAS_FILE_IO      1
    #define E9_HAS_TACTIC_B0    1
#endif

namespace e9platform {

/*
 * Memory protection flags (platform-independent)
 */
enum MemoryProt : int {
    PROT_NONE_  = 0,
    PROT_READ_  = 1,
    PROT_WRITE_ = 2,
    PROT_EXEC_  = 4
};

/*
 * Memory mapping flags
 */
enum MapFlags : int {
    MAP_PRIVATE_   = 1,
    MAP_SHARED_    = 2,
    MAP_ANONYMOUS_ = 4,
    MAP_FIXED_     = 8
};

/*
 * Buffer structure for binary data
 */
struct Buffer {
    uint8_t *data;
    size_t size;
    size_t capacity;
    bool owned;         // If true, destructor frees data

    Buffer() : data(nullptr), size(0), capacity(0), owned(false) {}
    Buffer(size_t cap);
    Buffer(uint8_t *d, size_t s, bool own = false)
        : data(d), size(s), capacity(s), owned(own) {}
    Buffer(Buffer &&other) noexcept;
    Buffer &operator=(Buffer &&other) noexcept;
    ~Buffer();

    // Disable copy
    Buffer(const Buffer&) = delete;
    Buffer &operator=(const Buffer&) = delete;

    bool resize(size_t new_size);
    bool reserve(size_t new_capacity);
    void clear();
};

/*
 * Memory manager interface
 */
class IMemoryManager {
public:
    virtual ~IMemoryManager() = default;

    // Allocate memory (like malloc)
    virtual void *allocate(size_t size) = 0;

    // Allocate aligned memory
    virtual void *allocateAligned(size_t size, size_t alignment) = 0;

    // Free memory
    virtual void deallocate(void *ptr) = 0;

    // Map memory at specific address (may not be supported on all platforms)
    virtual void *mapMemory(void *hint, size_t size, int prot, int flags) = 0;

    // Unmap memory
    virtual bool unmapMemory(void *addr, size_t size) = 0;

    // Change memory protection
    virtual bool protectMemory(void *addr, size_t size, int prot) = 0;

    // Check if mmap-style operations are supported
    virtual bool supportsMmap() const = 0;
};

/*
 * File I/O interface
 */
class IFileIO {
public:
    virtual ~IFileIO() = default;

    // Read entire file into buffer
    virtual Buffer readFile(const char *path) = 0;

    // Write buffer to file
    virtual bool writeFile(const char *path, const uint8_t *data, size_t size) = 0;

    // Append to file
    virtual bool appendFile(const char *path, const uint8_t *data, size_t size) = 0;

    // Check if file exists
    virtual bool fileExists(const char *path) = 0;

    // Get file size
    virtual size_t getFileSize(const char *path) = 0;

    // Delete file
    virtual bool deleteFile(const char *path) = 0;
};

/*
 * Callback for handling patch events (for IDE integration)
 */
using PatchCallback = std::function<void(intptr_t addr, size_t size, const uint8_t *data)>;
using ProgressCallback = std::function<void(size_t current, size_t total, const char *message)>;
using ErrorCallback = std::function<void(int code, const char *message)>;

/*
 * Event handler interface for IDE integration
 */
class IEventHandler {
public:
    virtual ~IEventHandler() = default;

    // Called when a patch is applied
    virtual void onPatchApplied(intptr_t addr, size_t size, const uint8_t *data) = 0;

    // Called for progress updates
    virtual void onProgress(size_t current, size_t total, const char *message) = 0;

    // Called on errors
    virtual void onError(int code, const char *message) = 0;

    // Called when rewriting is complete
    virtual void onComplete(bool success, const char *outputPath) = 0;
};

/*
 * Platform context - holds all platform-specific implementations
 */
class PlatformContext {
public:
    IMemoryManager *memory;
    IFileIO *fileIO;
    IEventHandler *events;

    PlatformContext();
    ~PlatformContext();

    // Get singleton instance
    static PlatformContext &getInstance();

    // Initialize with custom implementations
    void init(IMemoryManager *mem, IFileIO *file, IEventHandler *evt = nullptr);

    // Reset to default implementations
    void reset();

private:
    bool ownsMemory;
    bool ownsFileIO;
    bool ownsEvents;
};

/*
 * Platform initialization (call once at startup)
 */
void platformInit();

/*
 * Platform-specific random number generation
 */
uint64_t platformRandom();

/*
 * Get current timestamp (milliseconds)
 */
uint64_t platformTimestamp();

/*
 * Platform-specific logging
 */
void platformLog(int level, const char *format, ...);

/*
 * Log levels
 */
enum LogLevel {
    LOG_DEBUG = 0,
    LOG_INFO = 1,
    LOG_WARNING = 2,
    LOG_ERROR = 3
};

} // namespace e9platform

/*
 * Convenience macros for accessing platform services
 */
#define E9_MEMORY()   (e9platform::PlatformContext::getInstance().memory)
#define E9_FILE_IO()  (e9platform::PlatformContext::getInstance().fileIO)
#define E9_EVENTS()   (e9platform::PlatformContext::getInstance().events)

#endif /* E9PLATFORM_H */
