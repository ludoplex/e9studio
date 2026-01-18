/*
 * e9studio_config.h
 * Central Configuration Header for E9Studio
 *
 * This header defines feature test macros and common configuration
 * that must be included BEFORE any system headers.
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

#ifndef E9STUDIO_CONFIG_H
#define E9STUDIO_CONFIG_H

/*
 * POSIX Feature Test Macros
 *
 * These must be defined before including any system headers to ensure
 * proper function declarations are available:
 *
 * _GNU_SOURCE: Enables GNU extensions including:
 *   - readlink() with standard prototype
 *   - Additional string functions
 *   - Extended file operations
 *
 * _DEFAULT_SOURCE: Enables default POSIX/BSD definitions including:
 *   - usleep() for microsecond delays
 *   - Various BSD-derived functions
 *
 * Note: _GNU_SOURCE implies _DEFAULT_SOURCE on glibc systems, but we
 * define both explicitly for clarity and cross-libc compatibility.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

/*
 * Cosmopolitan Libc Detection
 *
 * When building with cosmocc, __COSMOPOLITAN__ is defined and we MUST
 * use Cosmopolitan-specific APIs (e.g., GetProgramExecutableName() instead
 * of readlink("/proc/self/exe")) for correct cross-platform behavior.
 *
 * Cosmopolitan provides portable implementations that work across all
 * supported platforms (Linux, macOS, Windows, *BSD). Using standard POSIX
 * APIs may work on some platforms but fail on others.
 */
#ifdef __COSMOPOLITAN__
#define E9STUDIO_COSMO 1
#else
#define E9STUDIO_COSMO 0
#endif

/*
 * Debug/Assert Configuration
 */
#ifndef E9STUDIO_DEBUG
#ifdef NDEBUG
#define E9STUDIO_DEBUG 0
#else
#define E9STUDIO_DEBUG 1
#endif
#endif

/*
 * String Copy with Truncation Detection
 *
 * E9_STRCPY_SAFE(dst, dst_size, src) - Copy string with truncation checking
 *
 * In debug builds (E9STUDIO_DEBUG=1), logs a warning via fprintf(stderr,...)
 * when truncation occurs. In release builds, silently truncates.
 *
 * Returns: number of characters that would have been written (like snprintf)
 *          If return >= dst_size, truncation occurred.
 */
#include <stdio.h>
#include <string.h>

static inline int e9_strcpy_safe(char *dst, size_t dst_size, const char *src,
                                  const char *file, int line)
{
    int ret = snprintf(dst, dst_size, "%s", src);
#if E9STUDIO_DEBUG
    if (ret >= (int)dst_size) {
        fprintf(stderr, "[E9Studio] Warning: string truncated at %s:%d "
                "(needed %d, had %zu)\n", file, line, ret + 1, dst_size);
    }
#else
    (void)file;
    (void)line;
#endif
    return ret;
}

#define E9_STRCPY_SAFE(dst, dst_size, src) \
    e9_strcpy_safe((dst), (dst_size), (src), __FILE__, __LINE__)

#endif /* E9STUDIO_CONFIG_H */
