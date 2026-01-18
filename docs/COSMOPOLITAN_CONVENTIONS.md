# Cosmopolitan Coding Conventions

Reference document for aligning e9patch/e9studio with jart/cosmopolitan patterns.

## 1. Include Guards

```c
// Full path-based guard with trailing underscore
#ifndef COSMOPOLITAN_LIBC_CALLS_SYSCALLS_H_
#define COSMOPOLITAN_LIBC_CALLS_SYSCALLS_H_
// ...
#endif /* COSMOPOLITAN_LIBC_CALLS_SYSCALLS_H_ */
```

**For e9patch:**
```c
#ifndef E9PATCH_WASM_E9WASM_HOST_H_
#define E9PATCH_WASM_E9WASM_HOST_H_
```

## 2. Platform Detection Pattern

```c
// Compile-time: check what's supported
#if defined(__COSMOPOLITAN__)
    // Cosmopolitan APIs - works on ALL platforms
#elif defined(__linux__)
    // Native Linux only
#elif defined(__APPLE__)
    // Native macOS only
#elif defined(__FreeBSD__)
    // Native FreeBSD only
#else
    // Fallback
#endif

// Runtime: check what's running (Cosmopolitan provides these)
if (IsLinux()) { }
if (IsWindows()) { }
if (IsXnu()) { }
```

**Key Principle:** `__COSMOPOLITAN__` branch uses Cosmopolitan's portable APIs.
Other branches are for native (non-cosmocc) builds only.

## 3. Function Attributes

```c
// Memory allocation
void *malloc(size_t) attributeallocsize((1)) mallocesque;

// Parameter validation
int open(const char *, int, ...) paramsnonnull((1));

// Return value must be used
ssize_t read(int, void *, size_t) __wur;

// Function doesn't return
void exit(int) wontreturn;

// No side effects
size_t strlen(const char *) nosideeffect paramsnonnull();
```

## 4. Naming Conventions

| Type | Convention | Example |
|------|------------|---------|
| Public functions | snake_case | `get_exe_path()` |
| Internal functions | __prefix | `__getcwd()` |
| Diagnostic functions | CamelCase | `GetProgramExecutableName()` |
| Macros | UPPER_CASE | `ARRAYLEN()`, `ROUNDUP()` |
| Types | snake_case | `sig_atomic_t` |

## 5. Error Handling

```c
// Return -1 on error, set errno
int result = some_call();
if (result == -1) {
    // Check errno for specific error
    if (errno == ENOENT) {
        // Handle file not found
    }
    return -1;
}

// Document in comments
/**
 * @return 0 on success, or -1 w/ errno
 */
```

## 6. File Organization

```
project/
├── libc/           # Core library (mirrored in test/)
│   ├── calls/      # System call wrappers
│   ├── runtime/    # Runtime support
│   └── *.h         # Headers
├── tool/           # Build tools
├── test/           # Tests (mirrors source structure)
│   └── libc/
│       └── calls/
└── build/          # Build configuration
```

**Platform-specific file suffixes:**
- `-nt.c` - Windows NT
- `-linux.c` - Linux
- `-xnu.c` - macOS
- `-freebsd.c` - FreeBSD
- `-sysv.c` - POSIX/System V

## 7. Header Structure

```c
/*-*- mode:c;indent-tabs-mode:nil;c-basic-offset:2;tab-width:8;coding:utf-8 -*-│
│ vi: set et ft=c ts=2 sts=2 sw=2 fenc=utf-8                               :vi │
╞══════════════════════════════════════════════════════════════════════════════╡
│ Copyright 2024 E9Patch Contributors                                         │
│ ISC License                                                                  │
╚─────────────────────────────────────────────────────────────────────────────*/
#ifndef E9PATCH_MODULE_HEADER_H_
#define E9PATCH_MODULE_HEADER_H_

COSMOPOLITAN_C_START_

/*───────────────────────────────────────────────────────────────────────────│─╗
│ e9patch § section name                                                    ─╬─│┼
╚────────────────────────────────────────────────────────────────────────────│*/

// declarations...

COSMOPOLITAN_C_END_
#endif /* E9PATCH_MODULE_HEADER_H_ */
```

## 8. Cosmopolitan APIs to Prefer

When `__COSMOPOLITAN__` is defined, use these instead of raw syscalls:

| Instead of | Use |
|------------|-----|
| `readlink("/proc/self/exe", ...)` | `GetProgramExecutableName()` |
| Raw `mmap()` | Cosmopolitan's `mmap()` wrapper |
| Platform-specific file ops | POSIX APIs (Cosmopolitan emulates) |
| `#ifdef __linux__` only | `#if defined(__COSMOPOLITAN__) \|\| defined(__linux__)` |

## 9. Build System

```makefile
# Package declaration
PKGS += E9STUDIO

# Sources and objects
E9STUDIO_SRCS = $(wildcard src/e9patch/*.c)
E9STUDIO_OBJS = $(E9STUDIO_SRCS:%.c=o/$(MODE)/%.o)

# Dependencies
E9STUDIO_DIRECTDEPS = \
    LIBC_CALLS \
    LIBC_STDIO

# Build modes
# make MODE=dbg   - Debug
# make MODE=opt   - Optimized
# make MODE=tiny  - Small binary
```

## 10. Documentation Style

```c
/**
 * Brief description of function.
 *
 * Detailed explanation if needed.
 *
 * @param name description of parameter
 * @return description of return value, or -1 w/ errno
 * @see related_function()
 * @asyncsignalsafe
 * @threadsafe
 */
int function_name(int param);
```

## 11. Common Macros

```c
#define MAX(X, Y)        ((Y) < (X) ? (X) : (Y))
#define MIN(X, Y)        ((Y) > (X) ? (X) : (Y))
#define ARRAYLEN(A)      (sizeof(A) / sizeof(*(A)))
#define ROUNDUP(X, K)    (((X) + (K) - 1) & -(K))
#define STRINGIFY(A)     __STRINGIFY(A)
```

## 12. Self-Modification / APE Patterns

```c
#ifdef __COSMOPOLITAN__
// Use Cosmopolitan's APIs for APE operations
extern char *GetProgramExecutableName(void);

// Code morphing for self-modification
void __morph_begin(void);
// ... modify code ...
void __morph_end(void);

// Clear instruction cache after code modification
void __clear_cache(void *, void *);
#endif
```

## Summary: Alignment Checklist

- [ ] Include guards follow `PROJECT_PATH_FILE_H_` pattern
- [ ] Platform detection uses `#if defined(__COSMOPOLITAN__)` first
- [ ] Cosmopolitan APIs used when `__COSMOPOLITAN__` defined
- [ ] Function attributes applied (`paramsnonnull`, `__wur`, etc.)
- [ ] Error handling returns -1 with errno
- [ ] Naming follows snake_case / UPPER_CASE conventions
- [ ] Headers have decorative borders and proper structure
- [ ] Documentation uses Doxygen-style `@param`, `@return`
- [ ] Test structure mirrors source structure
- [ ] Build system uses modular package declarations
