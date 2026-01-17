/*
 * e9platform_wasm.cpp
 * WebAssembly platform implementation for browser/Chrome integration
 *
 * Provides:
 * - Memory management via linear memory
 * - File I/O via JavaScript bridge or WASI
 * - Event callbacks for IDE integration
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

#include "e9platform.h"

#if defined(E9_PLATFORM_WASM)

#include <cstdlib>
#include <cstdio>
#include <cstdarg>
#include <cstring>

#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#include <emscripten/bind.h>
#include <emscripten/val.h>
#endif

namespace e9platform {

/*
 * Buffer implementation (same as native)
 */
Buffer::Buffer(size_t cap) : data(nullptr), size(0), capacity(0), owned(true) {
    if (cap > 0) {
        data = static_cast<uint8_t*>(malloc(cap));
        if (data) {
            capacity = cap;
        }
    }
}

Buffer::Buffer(Buffer &&other) noexcept
    : data(other.data), size(other.size), capacity(other.capacity), owned(other.owned) {
    other.data = nullptr;
    other.size = 0;
    other.capacity = 0;
    other.owned = false;
}

Buffer &Buffer::operator=(Buffer &&other) noexcept {
    if (this != &other) {
        if (owned && data) free(data);
        data = other.data;
        size = other.size;
        capacity = other.capacity;
        owned = other.owned;
        other.data = nullptr;
        other.size = 0;
        other.capacity = 0;
        other.owned = false;
    }
    return *this;
}

Buffer::~Buffer() {
    if (owned && data) free(data);
}

bool Buffer::resize(size_t new_size) {
    if (new_size > capacity && !reserve(new_size)) return false;
    size = new_size;
    return true;
}

bool Buffer::reserve(size_t new_capacity) {
    if (new_capacity <= capacity) return true;
    uint8_t *new_data = static_cast<uint8_t*>(realloc(data, new_capacity));
    if (!new_data) return false;
    data = new_data;
    capacity = new_capacity;
    owned = true;
    return true;
}

void Buffer::clear() { size = 0; }

/*
 * WASM Memory Manager
 * Uses standard malloc/free - no mmap support
 */
class WasmMemoryManager : public IMemoryManager {
public:
    void *allocate(size_t size) override {
        return malloc(size);
    }

    void *allocateAligned(size_t size, size_t alignment) override {
        // WASM doesn't have posix_memalign, use aligned_alloc if available
        #if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
        return aligned_alloc(alignment, size);
        #else
        // Manual alignment
        void *ptr = malloc(size + alignment);
        if (!ptr) return nullptr;
        void *aligned = (void*)(((uintptr_t)ptr + alignment) & ~(alignment - 1));
        ((void**)aligned)[-1] = ptr;  // Store original pointer
        return aligned;
        #endif
    }

    void deallocate(void *ptr) override {
        free(ptr);
    }

    void *mapMemory(void *, size_t size, int, int) override {
        // WASM doesn't support mmap - just allocate
        return malloc(size);
    }

    bool unmapMemory(void *addr, size_t) override {
        free(addr);
        return true;
    }

    bool protectMemory(void *, size_t, int) override {
        // WASM doesn't support memory protection changes
        return true;
    }

    bool supportsMmap() const override {
        return false;
    }
};

/*
 * JavaScript bridge for file I/O
 * Uses Emscripten's EM_JS to call JavaScript functions
 */
#ifdef __EMSCRIPTEN__

// JavaScript callback storage
EM_JS(void, js_log, (int level, const char *msg), {
    const message = UTF8ToString(msg);
    switch (level) {
        case 0: console.debug('[e9patch]', message); break;
        case 1: console.info('[e9patch]', message); break;
        case 2: console.warn('[e9patch]', message); break;
        case 3: console.error('[e9patch]', message); break;
        default: console.log('[e9patch]', message);
    }
});

EM_JS(int, js_file_exists, (const char *path), {
    const pathStr = UTF8ToString(path);
    if (typeof window !== 'undefined' && window.e9patchFileSystem) {
        return window.e9patchFileSystem.exists(pathStr) ? 1 : 0;
    }
    return 0;
});

EM_JS(int, js_file_size, (const char *path), {
    const pathStr = UTF8ToString(path);
    if (typeof window !== 'undefined' && window.e9patchFileSystem) {
        return window.e9patchFileSystem.getSize(pathStr);
    }
    return 0;
});

EM_JS(int, js_read_file, (const char *path, uint8_t *buffer, int maxSize), {
    const pathStr = UTF8ToString(path);
    if (typeof window !== 'undefined' && window.e9patchFileSystem) {
        const data = window.e9patchFileSystem.read(pathStr);
        if (data) {
            const len = Math.min(data.length, maxSize);
            HEAPU8.set(data.subarray(0, len), buffer);
            return len;
        }
    }
    return -1;
});

EM_JS(int, js_write_file, (const char *path, const uint8_t *data, int size), {
    const pathStr = UTF8ToString(path);
    if (typeof window !== 'undefined' && window.e9patchFileSystem) {
        const buffer = HEAPU8.slice(data, data + size);
        return window.e9patchFileSystem.write(pathStr, buffer) ? 0 : -1;
    }
    return -1;
});

EM_JS(void, js_on_patch_applied, (int addr, int size, const uint8_t *data), {
    if (typeof window !== 'undefined' && window.e9patchCallbacks &&
        window.e9patchCallbacks.onPatchApplied) {
        const buffer = HEAPU8.slice(data, data + size);
        window.e9patchCallbacks.onPatchApplied(addr, buffer);
    }
});

EM_JS(void, js_on_progress, (int current, int total, const char *msg), {
    if (typeof window !== 'undefined' && window.e9patchCallbacks &&
        window.e9patchCallbacks.onProgress) {
        window.e9patchCallbacks.onProgress(current, total, UTF8ToString(msg));
    }
});

EM_JS(void, js_on_error, (int code, const char *msg), {
    if (typeof window !== 'undefined' && window.e9patchCallbacks &&
        window.e9patchCallbacks.onError) {
        window.e9patchCallbacks.onError(code, UTF8ToString(msg));
    }
});

EM_JS(void, js_on_complete, (int success, const char *path), {
    if (typeof window !== 'undefined' && window.e9patchCallbacks &&
        window.e9patchCallbacks.onComplete) {
        window.e9patchCallbacks.onComplete(success !== 0, UTF8ToString(path));
    }
});

EM_JS(double, js_get_timestamp, (), {
    return Date.now();
});

EM_JS(double, js_get_random, (), {
    return Math.random() * 0xFFFFFFFF;
});

#else
// Stub implementations for non-Emscripten WASM (WASI)
void js_log(int, const char *) {}
int js_file_exists(const char *) { return 0; }
int js_file_size(const char *) { return 0; }
int js_read_file(const char *, uint8_t *, int) { return -1; }
int js_write_file(const char *, const uint8_t *, int) { return -1; }
void js_on_patch_applied(int, int, const uint8_t *) {}
void js_on_progress(int, int, const char *) {}
void js_on_error(int, const char *) {}
void js_on_complete(int, const char *) {}
double js_get_timestamp() { return 0; }
double js_get_random() { return 0; }
#endif

/*
 * WASM File I/O - bridges to JavaScript
 */
class WasmFileIO : public IFileIO {
public:
    Buffer readFile(const char *path) override {
        int size = js_file_size(path);
        if (size <= 0) {
            return Buffer();
        }

        Buffer buf(static_cast<size_t>(size));
        if (!buf.data) {
            return Buffer();
        }

        int bytesRead = js_read_file(path, buf.data, size);
        if (bytesRead < 0) {
            return Buffer();
        }

        buf.size = static_cast<size_t>(bytesRead);
        return buf;
    }

    bool writeFile(const char *path, const uint8_t *data, size_t size) override {
        return js_write_file(path, data, static_cast<int>(size)) == 0;
    }

    bool appendFile(const char *path, const uint8_t *data, size_t size) override {
        // For simplicity, read existing content and write combined
        Buffer existing = readFile(path);
        Buffer combined(existing.size + size);
        if (!combined.data) return false;

        if (existing.size > 0) {
            memcpy(combined.data, existing.data, existing.size);
        }
        memcpy(combined.data + existing.size, data, size);
        combined.size = existing.size + size;

        return writeFile(path, combined.data, combined.size);
    }

    bool fileExists(const char *path) override {
        return js_file_exists(path) != 0;
    }

    size_t getFileSize(const char *path) override {
        int size = js_file_size(path);
        return size > 0 ? static_cast<size_t>(size) : 0;
    }

    bool deleteFile(const char *) override {
        // Not typically supported in browser environment
        return false;
    }
};

/*
 * WASM Event Handler - bridges to JavaScript callbacks
 */
class WasmEventHandler : public IEventHandler {
public:
    void onPatchApplied(intptr_t addr, size_t size, const uint8_t *data) override {
        js_on_patch_applied(static_cast<int>(addr), static_cast<int>(size), data);
    }

    void onProgress(size_t current, size_t total, const char *message) override {
        js_on_progress(static_cast<int>(current), static_cast<int>(total), message);
    }

    void onError(int code, const char *message) override {
        js_on_error(code, message);
    }

    void onComplete(bool success, const char *outputPath) override {
        js_on_complete(success ? 1 : 0, outputPath);
    }
};

/*
 * Platform context implementation
 */
static WasmMemoryManager defaultMemory;
static WasmFileIO defaultFileIO;
static WasmEventHandler defaultEvents;
static PlatformContext *globalContext = nullptr;

PlatformContext::PlatformContext()
    : memory(&defaultMemory), fileIO(&defaultFileIO), events(&defaultEvents),
      ownsMemory(false), ownsFileIO(false), ownsEvents(false) {}

PlatformContext::~PlatformContext() {
    if (ownsMemory && memory != &defaultMemory) delete memory;
    if (ownsFileIO && fileIO != &defaultFileIO) delete fileIO;
    if (ownsEvents && events != &defaultEvents) delete events;
}

PlatformContext &PlatformContext::getInstance() {
    if (!globalContext) {
        globalContext = new PlatformContext();
    }
    return *globalContext;
}

void PlatformContext::init(IMemoryManager *mem, IFileIO *file, IEventHandler *evt) {
    if (mem) {
        if (ownsMemory && memory != &defaultMemory) delete memory;
        memory = mem;
        ownsMemory = true;
    }
    if (file) {
        if (ownsFileIO && fileIO != &defaultFileIO) delete fileIO;
        fileIO = file;
        ownsFileIO = true;
    }
    if (evt) {
        if (ownsEvents && events != &defaultEvents) delete events;
        events = evt;
        ownsEvents = true;
    }
}

void PlatformContext::reset() {
    if (ownsMemory && memory != &defaultMemory) delete memory;
    if (ownsFileIO && fileIO != &defaultFileIO) delete fileIO;
    if (ownsEvents && events != &defaultEvents) delete events;
    memory = &defaultMemory;
    fileIO = &defaultFileIO;
    events = &defaultEvents;
    ownsMemory = false;
    ownsFileIO = false;
    ownsEvents = false;
}

void platformInit() {
    PlatformContext::getInstance();
    js_log(LOG_INFO, "E9Patch WASM initialized");
}

uint64_t platformRandom() {
    return static_cast<uint64_t>(js_get_random());
}

uint64_t platformTimestamp() {
    return static_cast<uint64_t>(js_get_timestamp());
}

void platformLog(int level, const char *format, ...) {
    char buffer[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    js_log(level, buffer);
}

} // namespace e9platform

/*
 * Exported WASM API functions
 */
#ifdef __EMSCRIPTEN__

extern "C" {

EMSCRIPTEN_KEEPALIVE
void e9patch_init() {
    e9platform::platformInit();
}

EMSCRIPTEN_KEEPALIVE
int e9patch_get_version() {
    return 1;  // API version
}

} // extern "C"

#endif

#endif /* E9_PLATFORM_WASM */
