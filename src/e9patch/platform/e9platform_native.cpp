/*
 * e9platform_native.cpp
 * Native (POSIX/Linux) platform implementation
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

#include "e9platform.h"

#if defined(E9_PLATFORM_POSIX) || defined(E9_PLATFORM_COSMOPOLITAN)

#include <cstdlib>
#include <cstdio>
#include <cstdarg>
#include <ctime>
#include <cerrno>

#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>

#ifdef __linux__
#include <sys/random.h>
#endif

namespace e9platform {

/*
 * Buffer implementation
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
        if (owned && data) {
            free(data);
        }
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
    if (owned && data) {
        free(data);
    }
}

bool Buffer::resize(size_t new_size) {
    if (new_size > capacity) {
        if (!reserve(new_size)) {
            return false;
        }
    }
    size = new_size;
    return true;
}

bool Buffer::reserve(size_t new_capacity) {
    if (new_capacity <= capacity) {
        return true;
    }
    uint8_t *new_data = static_cast<uint8_t*>(realloc(data, new_capacity));
    if (!new_data) {
        return false;
    }
    data = new_data;
    capacity = new_capacity;
    owned = true;
    return true;
}

void Buffer::clear() {
    size = 0;
}

/*
 * Native memory manager
 */
class NativeMemoryManager : public IMemoryManager {
public:
    void *allocate(size_t size) override {
        return malloc(size);
    }

    void *allocateAligned(size_t size, size_t alignment) override {
        void *ptr = nullptr;
        if (posix_memalign(&ptr, alignment, size) != 0) {
            return nullptr;
        }
        return ptr;
    }

    void deallocate(void *ptr) override {
        free(ptr);
    }

    void *mapMemory(void *hint, size_t size, int prot, int flags) override {
        int sys_prot = 0;
        if (prot & PROT_READ_)  sys_prot |= PROT_READ;
        if (prot & PROT_WRITE_) sys_prot |= PROT_WRITE;
        if (prot & PROT_EXEC_)  sys_prot |= PROT_EXEC;

        int sys_flags = 0;
        if (flags & MAP_PRIVATE_)   sys_flags |= MAP_PRIVATE;
        if (flags & MAP_SHARED_)    sys_flags |= MAP_SHARED;
        if (flags & MAP_ANONYMOUS_) sys_flags |= MAP_ANONYMOUS;
        if (flags & MAP_FIXED_)     sys_flags |= MAP_FIXED;

        void *result = mmap(hint, size, sys_prot, sys_flags, -1, 0);
        if (result == MAP_FAILED) {
            return nullptr;
        }
        return result;
    }

    bool unmapMemory(void *addr, size_t size) override {
        return munmap(addr, size) == 0;
    }

    bool protectMemory(void *addr, size_t size, int prot) override {
        int sys_prot = 0;
        if (prot & PROT_READ_)  sys_prot |= PROT_READ;
        if (prot & PROT_WRITE_) sys_prot |= PROT_WRITE;
        if (prot & PROT_EXEC_)  sys_prot |= PROT_EXEC;
        return mprotect(addr, size, sys_prot) == 0;
    }

    bool supportsMmap() const override {
        return true;
    }
};

/*
 * Native file I/O
 */
class NativeFileIO : public IFileIO {
public:
    Buffer readFile(const char *path) override {
        int fd = open(path, O_RDONLY);
        if (fd < 0) {
            return Buffer();
        }

        struct stat st;
        if (fstat(fd, &st) < 0) {
            close(fd);
            return Buffer();
        }

        size_t file_size = static_cast<size_t>(st.st_size);
        Buffer buf(file_size);
        if (!buf.data) {
            close(fd);
            return Buffer();
        }

        size_t total_read = 0;
        while (total_read < file_size) {
            ssize_t n = read(fd, buf.data + total_read, file_size - total_read);
            if (n <= 0) {
                if (n < 0 && errno == EINTR) continue;
                break;
            }
            total_read += n;
        }

        close(fd);
        buf.size = total_read;
        return buf;
    }

    bool writeFile(const char *path, const uint8_t *data, size_t size) override {
        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) {
            return false;
        }

        size_t total_written = 0;
        while (total_written < size) {
            ssize_t n = write(fd, data + total_written, size - total_written);
            if (n <= 0) {
                if (n < 0 && errno == EINTR) continue;
                close(fd);
                return false;
            }
            total_written += n;
        }

        close(fd);
        return true;
    }

    bool appendFile(const char *path, const uint8_t *data, size_t size) override {
        int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd < 0) {
            return false;
        }

        size_t total_written = 0;
        while (total_written < size) {
            ssize_t n = write(fd, data + total_written, size - total_written);
            if (n <= 0) {
                if (n < 0 && errno == EINTR) continue;
                close(fd);
                return false;
            }
            total_written += n;
        }

        close(fd);
        return true;
    }

    bool fileExists(const char *path) override {
        return access(path, F_OK) == 0;
    }

    size_t getFileSize(const char *path) override {
        struct stat st;
        if (stat(path, &st) < 0) {
            return 0;
        }
        return static_cast<size_t>(st.st_size);
    }

    bool deleteFile(const char *path) override {
        return unlink(path) == 0;
    }
};

/*
 * Default event handler (no-op)
 */
class DefaultEventHandler : public IEventHandler {
public:
    void onPatchApplied(intptr_t, size_t, const uint8_t*) override {}
    void onProgress(size_t, size_t, const char*) override {}
    void onError(int, const char*) override {}
    void onComplete(bool, const char*) override {}
};

/*
 * Platform context implementation
 */
static NativeMemoryManager defaultMemory;
static NativeFileIO defaultFileIO;
static DefaultEventHandler defaultEvents;
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
    // Ensure global context exists
    PlatformContext::getInstance();
}

uint64_t platformRandom() {
#ifdef __linux__
    uint64_t value;
    if (getrandom(&value, sizeof(value), 0) == sizeof(value)) {
        return value;
    }
#endif
    // Fallback to /dev/urandom
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        uint64_t value;
        if (read(fd, &value, sizeof(value)) == sizeof(value)) {
            close(fd);
            return value;
        }
        close(fd);
    }
    // Last resort: time-based
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    return (uint64_t)tv.tv_sec * 1000000ULL + tv.tv_usec;
}

uint64_t platformTimestamp() {
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    return (uint64_t)tv.tv_sec * 1000ULL + tv.tv_usec / 1000;
}

void platformLog(int level, const char *format, ...) {
    const char *prefix;
    switch (level) {
        case LOG_DEBUG:   prefix = "debug"; break;
        case LOG_INFO:    prefix = "info"; break;
        case LOG_WARNING: prefix = "warning"; break;
        case LOG_ERROR:   prefix = "error"; break;
        default:          prefix = "log"; break;
    }

    fprintf(stderr, "[%s] ", prefix);

    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);

    fprintf(stderr, "\n");
}

} // namespace e9platform

#endif /* E9_PLATFORM_POSIX || E9_PLATFORM_COSMOPOLITAN */
