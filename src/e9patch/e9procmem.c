/*
 * e9procmem.c - Unified Process Memory API Implementation
 *
 * Backends, selected at RUN time so one APE binary serves every OS:
 *   Linux:   pread/pwrite on /proc/PID/mem (no stop required; the kernel
 *            forces writes through page protections)
 *   Windows: OpenProcess + NtReadVirtualMemory / WriteProcessMemory /
 *            VirtualProtectEx, declared by Cosmopolitan's libc/nt headers
 *            (64-bit HANDLEs, ms_abi calling convention)
 *   macOS, BSD: remote access not implemented (reported as such)
 *   Self:    mprotect + direct memory access
 *
 * Under cosmocc the host OS is only known at run time, so dispatch uses
 * IsLinux() / IsWindows() / IsXnu() from libc/dce.h rather than #ifdef.
 * Native (non-APE) POSIX builds keep the compile-time fallback in get_os();
 * the Windows backend is only available through cosmocc.
 *
 * Copyright (C) 2024 E9Studio Contributors
 * License: GPLv3+
 */

#if defined(__COSMOPOLITAN__) && !defined(_COSMO_SOURCE)
#define _COSMO_SOURCE
#endif
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "e9procmem.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef __COSMOPOLITAN__
#include <cosmo.h>                        /* IsLinux() IsWindows() IsXnu() IsBsd() */
#include <libc/nt/enum/pageflags.h>       /* kNtPage* */
#include <libc/nt/enum/processaccess.h>   /* kNtProcessVm* */
#include <libc/nt/memory.h>               /* WriteProcessMemory VirtualProtectEx */
#include <libc/nt/ntdll.h>                /* NtReadVirtualMemory */
#include <libc/nt/process.h>              /* OpenProcess */
#include <libc/nt/runtime.h>              /* CloseHandle GetLastError */
#define E9_HAVE_PROCFS 1
#define E9_HAVE_NT 1
#elif defined(__linux__)
#define E9_HAVE_PROCFS 1
#endif

/* ── Backend identifiers (stored in E9ProcHandle.backend) ─────────────── */

enum {
    E9_BACKEND_NONE   = 0,
    E9_BACKEND_SELF   = 1,
    E9_BACKEND_PROCFS = 2,
    E9_BACKEND_NT     = 3,
};

/* ── Platform detection ───────────────────────────────────────────────── */

static int get_os(void) {
#ifdef __COSMOPOLITAN__
    if (IsLinux()) return PROCMEM_OS_LINUX;
    if (IsWindows()) return PROCMEM_OS_WINDOWS;
    if (IsXnu()) return PROCMEM_OS_MACOS;
    if (IsBsd()) return PROCMEM_OS_BSD;
    return PROCMEM_OS_UNKNOWN;
#elif defined(__linux__)
    return PROCMEM_OS_LINUX;
#elif defined(__APPLE__)
    return PROCMEM_OS_MACOS;
#elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    return PROCMEM_OS_BSD;
#else
    return PROCMEM_OS_UNKNOWN;
#endif
}

static int get_arch(void) {
#if defined(__x86_64__) || defined(_M_X64)
    return PROCMEM_ARCH_X86_64;
#elif defined(__aarch64__) || defined(_M_ARM64)
    return PROCMEM_ARCH_AARCH64;
#else
    return PROCMEM_ARCH_UNKNOWN;
#endif
}

/* Which remote backend serves this OS in this build (NONE if unsupported). */
static int remote_backend(int os) {
#ifdef E9_HAVE_PROCFS
    if (os == PROCMEM_OS_LINUX) return E9_BACKEND_PROCFS;
#endif
#ifdef E9_HAVE_NT
    if (os == PROCMEM_OS_WINDOWS) return E9_BACKEND_NT;
#endif
    (void)os;
    return E9_BACKEND_NONE;
}

static size_t page_size(void) {
    long n = sysconf(_SC_PAGESIZE);
    return n > 0 ? (size_t)n : 4096;
}

static void fail(E9ProcHandle *handle, int code, const char *what,
                 uint64_t addr, const char *detail) {
    handle->error_code = code;
    snprintf(handle->error_msg, sizeof(handle->error_msg),
             "%s failed at 0x%llx: %s", what, (unsigned long long)addr, detail);
}

void e9_procmem_get_platform(E9PlatformInfo *info) {
    static const char *names[] = {"self", "self", "procfs", "nt"};
    memset(info, 0, sizeof(*info));
    info->os = get_os();
    info->arch = get_arch();
    info->page_size = (uint32_t)page_size();
    info->can_self = 1;
    int backend = remote_backend(info->os);
    info->can_remote = backend != E9_BACKEND_NONE;
    strncpy(info->backend, names[backend], sizeof(info->backend) - 1);
}

/* ── Linux: /proc/PID/mem ─────────────────────────────────────────────── */

#ifdef E9_HAVE_PROCFS
static int procfs_open(E9ProcHandle *handle, int pid, uint32_t flags) {
    char path[64];
    int mode = (flags & (PROCMEM_WRITE | PROCMEM_EXECUTE)) ? O_RDWR : O_RDONLY;
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    int fd = open(path, mode | O_CLOEXEC);
    if (fd < 0) {
        int err = errno;
        handle->error_code = err;
        snprintf(handle->error_msg, sizeof(handle->error_msg),
                 "open(%s) failed: %s", path, strerror(err));
        return err == ENOENT ? PROCMEM_ERR_NOTFOUND : PROCMEM_ERR_ACCESS;
    }
    handle->handle = (uint64_t)fd;
    handle->backend = E9_BACKEND_PROCFS;
    return PROCMEM_OK;
}

static int procfs_xfer(E9ProcHandle *handle, uint64_t addr, void *buf,
                       size_t len, int writing) {
    int fd = (int)handle->handle;
    size_t done = 0;
    while (done < len) {
        ssize_t n = writing
            ? pwrite(fd, (const char *)buf + done, len - done, (off_t)(addr + done))
            : pread(fd, (char *)buf + done, len - done, (off_t)(addr + done));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) {
            int err = n < 0 ? errno : EIO;
            fail(handle, err, writing ? "pwrite(/proc/PID/mem)" : "pread(/proc/PID/mem)",
                 addr + done, n < 0 ? strerror(err) : "short transfer");
            return PROCMEM_ERR_ACCESS;
        }
        done += (size_t)n;
    }
    return PROCMEM_OK;
}
#endif

/* ── Windows: NT process handles (through cosmocc's libc/nt) ──────────── */

#ifdef E9_HAVE_NT
static int64_t nt_handle(const E9ProcHandle *handle) {
    return (int64_t)handle->handle;
}

static int nt_open(E9ProcHandle *handle, int pid, uint32_t flags) {
    uint32_t access = kNtProcessQueryLimitedInformation;
    if (flags & PROCMEM_READ) access |= kNtProcessVmRead;
    if (flags & (PROCMEM_WRITE | PROCMEM_EXECUTE))
        access |= kNtProcessVmWrite | kNtProcessVmOperation;

    int64_t h = OpenProcess(access, /*bInheritHandle=*/0, (uint32_t)pid);
    if (!h) {
        handle->error_code = (int32_t)GetLastError();
        snprintf(handle->error_msg, sizeof(handle->error_msg),
                 "OpenProcess failed for PID %d (GetLastError=%u)", pid,
                 (unsigned)handle->error_code);
        return PROCMEM_ERR_ACCESS;
    }
    handle->handle = (uint64_t)h;   /* full 64-bit HANDLE, never truncated */
    handle->backend = E9_BACKEND_NT;
    return PROCMEM_OK;
}

static int nt_xfer(E9ProcHandle *handle, uint64_t addr, void *buf, size_t len,
                   int writing) {
    char detail[96];
    if (writing) {
        uint64_t put = 0;
        if (WriteProcessMemory(nt_handle(handle), (void *)(uintptr_t)addr, buf, len, &put) &&
            put == len)
            return PROCMEM_OK;
        snprintf(detail, sizeof(detail), "%llu of %zu bytes, GetLastError=%u",
                 (unsigned long long)put, len, (unsigned)GetLastError());
        fail(handle, -1, "WriteProcessMemory", addr, detail);
    } else {
        size_t got = 0;
        uint32_t status = (uint32_t)NtReadVirtualMemory(
            nt_handle(handle), (const void *)(uintptr_t)addr, buf, len, &got);
        if (status == 0 && got == len) return PROCMEM_OK;
        snprintf(detail, sizeof(detail), "%zu of %zu bytes, NTSTATUS=0x%08x",
                 got, len, (unsigned)status);
        fail(handle, (int)status, "NtReadVirtualMemory", addr, detail);
    }
    return PROCMEM_ERR_ACCESS;
}

static int nt_protect(E9ProcHandle *handle, uint64_t addr, size_t len, uint32_t flags) {
    uint32_t prot = (flags & PROCMEM_EXECUTE)
        ? ((flags & PROCMEM_WRITE) ? kNtPageExecuteReadwrite : kNtPageExecuteRead)
        : ((flags & PROCMEM_WRITE) ? kNtPageReadwrite : kNtPageReadonly);
    uint32_t old = 0;
    if (VirtualProtectEx(nt_handle(handle), (void *)(uintptr_t)addr, len, prot, &old))
        return PROCMEM_OK;
    char detail[32];
    snprintf(detail, sizeof(detail), "GetLastError=%u", (unsigned)GetLastError());
    fail(handle, -1, "VirtualProtectEx", addr, detail);
    return PROCMEM_ERR_PERM;
}
#endif

/* ── Self-patching (all platforms) ────────────────────────────────────── */

static int self_protect(E9ProcHandle *handle, uint64_t addr, size_t len, int prot) {
    uint64_t mask = (uint64_t)page_size() - 1;
    uint64_t start = addr & ~mask;
    uint64_t end = (addr + len + mask) & ~mask;
    if (mprotect((void *)(uintptr_t)start, (size_t)(end - start), prot) != 0) {
        int err = errno;
        fail(handle, err, "mprotect", start, strerror(err));
        return PROCMEM_ERR_PERM;
    }
    return PROCMEM_OK;
}

static int self_xfer(E9ProcHandle *handle, uint64_t addr, void *buf, size_t len,
                     int writing) {
    if (!writing) {
        memcpy(buf, (const void *)(uintptr_t)addr, len);
        return PROCMEM_OK;
    }
    /* Covers every page in [addr, addr+len). Code pages become RWX, which
     * W^X systems (OpenBSD, Apple silicon) refuse; that surfaces as ERR_PERM. */
    int rc = self_protect(handle, addr, len, PROT_READ | PROT_WRITE | PROT_EXEC);
    if (rc != PROCMEM_OK) return rc;
    memcpy((void *)(uintptr_t)addr, buf, len);
    return PROCMEM_OK;
}

/* ── Public API ───────────────────────────────────────────────────────── */

int e9_procmem_open(E9ProcHandle *handle, int pid, uint32_t flags) {
    memset(handle, 0, sizeof(*handle));
    handle->pid = pid;
    handle->flags = flags;

    if (pid == 0 || pid == getpid()) {
        handle->pid = 0;
        handle->backend = E9_BACKEND_SELF;
        return PROCMEM_OK;
    }

    int os = get_os();
    switch (remote_backend(os)) {
#ifdef E9_HAVE_PROCFS
        case E9_BACKEND_PROCFS:
            if (kill(pid, 0) != 0 && errno == ESRCH) {
                handle->error_code = ESRCH;
                snprintf(handle->error_msg, sizeof(handle->error_msg),
                         "Process %d not found", pid);
                return PROCMEM_ERR_NOTFOUND;
            }
            return procfs_open(handle, pid, flags);
#endif
#ifdef E9_HAVE_NT
        case E9_BACKEND_NT:
            return nt_open(handle, pid, flags);
#endif
        default:
            handle->error_code = ENOSYS;
            snprintf(handle->error_msg, sizeof(handle->error_msg),
                     "Remote process access is not implemented on %s",
                     procmem_os_str(os));
            return PROCMEM_ERR_PLATFORM;
    }
}

void e9_procmem_close(E9ProcHandle *handle) {
#ifdef E9_HAVE_PROCFS
    if (handle->backend == E9_BACKEND_PROCFS) close((int)handle->handle);
#endif
#ifdef E9_HAVE_NT
    if (handle->backend == E9_BACKEND_NT && handle->handle) CloseHandle(nt_handle(handle));
#endif
    memset(handle, 0, sizeof(*handle));
}

static int xfer(E9ProcHandle *handle, uint64_t addr, void *buf, size_t len, int writing) {
    switch (handle->backend) {
        case E9_BACKEND_SELF:
            return self_xfer(handle, addr, buf, len, writing);
#ifdef E9_HAVE_PROCFS
        case E9_BACKEND_PROCFS:
            return procfs_xfer(handle, addr, buf, len, writing);
#endif
#ifdef E9_HAVE_NT
        case E9_BACKEND_NT:
            return nt_xfer(handle, addr, buf, len, writing);
#endif
        default:
            snprintf(handle->error_msg, sizeof(handle->error_msg), "handle is not open");
            return PROCMEM_ERR_PLATFORM;
    }
}

int e9_procmem_read(E9ProcHandle *handle, uint64_t addr, void *buf, size_t len) {
    return xfer(handle, addr, buf, len, 0);
}

int e9_procmem_write(E9ProcHandle *handle, uint64_t addr, const void *buf, size_t len) {
    return xfer(handle, addr, (void *)buf, len, 1);
}

int e9_procmem_protect(E9ProcHandle *handle, uint64_t addr, size_t len, uint32_t flags) {
    int prot = 0;
    if (flags & PROCMEM_READ) prot |= PROT_READ;
    if (flags & PROCMEM_WRITE) prot |= PROT_WRITE;
    if (flags & PROCMEM_EXECUTE) prot |= PROT_EXEC;

    switch (handle->backend) {
        case E9_BACKEND_SELF:
            return self_protect(handle, addr, len, prot);
#ifdef E9_HAVE_NT
        case E9_BACKEND_NT:
            return nt_protect(handle, addr, len, flags);
#endif
        default:
            /* /proc/PID/mem writes already bypass page protections; changing a
             * remote mapping's protection would need ptrace, which is not used. */
            snprintf(handle->error_msg, sizeof(handle->error_msg),
                     "protect is not supported for this backend");
            return PROCMEM_ERR_PLATFORM;
    }
}

void e9_procmem_flush_icache(uint64_t addr, size_t len) {
    /* Self only. x86-64 keeps instruction fetch coherent with the process's
     * own stores; AArch64 needs explicit maintenance, which the compiler
     * builtin performs using the CPU's real cache-line size (CTR_EL0). */
#if defined(__aarch64__)
    __builtin___clear_cache((char *)(uintptr_t)addr, (char *)(uintptr_t)(addr + len));
#else
    (void)addr;
    (void)len;
#endif
}

const char *e9_procmem_error(E9ProcHandle *handle) {
    return handle->error_msg[0] ? handle->error_msg : "No error";
}
