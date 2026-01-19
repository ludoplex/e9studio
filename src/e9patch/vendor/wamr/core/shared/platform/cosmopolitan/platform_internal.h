/*
 * platform_internal.h
 * Cosmopolitan Platform Layer Internals for WAMR
 *
 * This provides the platform abstraction that WAMR requires,
 * implemented using Cosmopolitan Libc APIs for cross-platform support.
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: Apache-2.0 (WAMR) / GPLv3+ (E9Studio integration)
 */

#ifndef PLATFORM_INTERNAL_H
#define PLATFORM_INTERNAL_H

#include "wamr_config.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <pthread.h>
#include <sys/mman.h>

#ifdef __COSMOPOLITAN__
#include <cosmo.h>
#include <libc/runtime/runtime.h>
#endif

/*
 * Basic types used by WAMR
 */
typedef uint8_t uint8;
typedef int8_t int8;
typedef uint16_t uint16;
typedef int16_t int16;
typedef uint32_t uint32;
typedef int32_t int32;
typedef uint64_t uint64;
typedef int64_t int64;

/*
 * Boolean type
 */
#ifndef bool
typedef uint8 bool;
#define true 1
#define false 0
#endif

/*
 * Logging
 */
typedef enum {
    BH_LOG_LEVEL_FATAL = 0,
    BH_LOG_LEVEL_ERROR = 1,
    BH_LOG_LEVEL_WARNING = 2,
    BH_LOG_LEVEL_DEBUG = 3,
    BH_LOG_LEVEL_VERBOSE = 4
} bh_log_level_t;

void bh_log(bh_log_level_t log_level, const char *file, int line,
            const char *fmt, ...);

#define LOG_FATAL(...) bh_log(BH_LOG_LEVEL_FATAL, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_ERROR(...) bh_log(BH_LOG_LEVEL_ERROR, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_WARNING(...) bh_log(BH_LOG_LEVEL_WARNING, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_DEBUG(...) bh_log(BH_LOG_LEVEL_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_VERBOSE(...) bh_log(BH_LOG_LEVEL_VERBOSE, __FILE__, __LINE__, __VA_ARGS__)

/*
 * Memory allocation
 */
void *os_malloc(size_t size);
void *os_realloc(void *ptr, size_t size);
void os_free(void *ptr);

#define BH_MALLOC os_malloc
#define BH_REALLOC os_realloc
#define BH_FREE os_free

/*
 * Memory mapping for JIT
 */
void *os_mmap(void *hint, size_t size, int prot, int flags);
void os_munmap(void *addr, size_t size);
int os_mprotect(void *addr, size_t size, int prot);

/* JIT-specific memory allocation (executable pages) */
void *os_mmap_jit(void *hint, size_t size);
int os_mmap_jit_finalize(void *addr, size_t size);
bool os_jit_available(void);

/* Memory commit/decommit (for lazy allocation) */
void *os_mem_commit(void *addr, size_t size, int flags);
void os_mem_decommit(void *addr, size_t size);

/*
 * Thread support
 */
typedef pthread_t korp_tid;
typedef pthread_mutex_t korp_mutex;
typedef pthread_cond_t korp_cond;
typedef pthread_rwlock_t korp_rwlock;

int os_thread_create(korp_tid *tid, void *(*start)(void *), void *arg,
                     unsigned int stack_size);
int os_thread_join(korp_tid tid, void **retval);
korp_tid os_self_thread(void);
void os_thread_exit(void *retval);

int os_mutex_init(korp_mutex *mutex);
int os_mutex_destroy(korp_mutex *mutex);
int os_mutex_lock(korp_mutex *mutex);
int os_mutex_unlock(korp_mutex *mutex);

int os_cond_init(korp_cond *cond);
int os_cond_destroy(korp_cond *cond);
int os_cond_wait(korp_cond *cond, korp_mutex *mutex);
int os_cond_signal(korp_cond *cond);
int os_cond_broadcast(korp_cond *cond);

int os_rwlock_init(korp_rwlock *lock);
int os_rwlock_destroy(korp_rwlock *lock);
int os_rwlock_rdlock(korp_rwlock *lock);
int os_rwlock_wrlock(korp_rwlock *lock);
int os_rwlock_unlock(korp_rwlock *lock);

/*
 * Time
 */
uint64 os_time_get_boot_microsecond(void);

/*
 * Instruction cache flush (required for JIT on ARM)
 */
void os_icache_flush(void *start, size_t len);

/*
 * Platform detection
 */
const char *os_get_platform_name(void);
bool os_is_linux(void);
bool os_is_macos(void);
bool os_is_windows(void);

/*
 * Signal handling (for bounds check traps)
 */
typedef void (*os_signal_handler)(int sig);
int os_signal_init(os_signal_handler handler);
void os_signal_destroy(void);

/*
 * Misc
 */
void os_printf(const char *fmt, ...);
int os_vprintf(const char *fmt, va_list ap);

#endif /* PLATFORM_INTERNAL_H */
