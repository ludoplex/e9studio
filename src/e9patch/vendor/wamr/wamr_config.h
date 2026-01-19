/*
 * wamr_config.h
 * E9Studio-specific WAMR Configuration
 *
 * This header configures WAMR (WebAssembly Micro Runtime) for use in
 * E9Studio's APE (Actually Portable Executable) environment.
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: Apache-2.0 (WAMR) / GPLv3+ (E9Studio integration)
 */

#ifndef WAMR_CONFIG_H
#define WAMR_CONFIG_H

/*
 * Build target detection
 * WAMR needs to know the target architecture for JIT code generation
 */
#if defined(__x86_64__) || defined(_M_X64)
#define BUILD_TARGET_X86_64 1
#define BUILD_TARGET "X86_64"
#elif defined(__aarch64__) || defined(_M_ARM64)
#define BUILD_TARGET_AARCH64 1
#define BUILD_TARGET "AARCH64"
#else
#error "Unsupported architecture for WAMR JIT"
#endif

/*
 * Execution modes
 *
 * We enable all modes and select at runtime based on:
 * 1. Command-line flags (--jit, --interp, --aot)
 * 2. Platform capabilities
 * 3. Module format (WASM vs pre-compiled AOT)
 */
#define WASM_ENABLE_INTERP      1   /* Classic interpreter */
#define WASM_ENABLE_FAST_INTERP 1   /* Optimized interpreter */
#define WASM_ENABLE_AOT         1   /* Ahead-of-time compilation */
#define WASM_ENABLE_JIT         0   /* LLVM JIT - disabled (too heavy) */
#define WASM_ENABLE_FAST_JIT    1   /* Fast JIT (no LLVM dependency) */

/*
 * WASI (WebAssembly System Interface)
 * Required for standard I/O, filesystem access in WASM modules
 */
#define WASM_ENABLE_LIBC_WASI    1
#define WASM_ENABLE_LIBC_BUILTIN 1

/*
 * Memory configuration
 * Tuned for binary rewriting workloads (large binaries)
 */
#define WASM_GLOBAL_HEAP_SIZE    (64 * 1024 * 1024)  /* 64 MB */
#define WASM_STACK_SIZE          (128 * 1024)        /* 128 KB */

/*
 * Feature flags
 */
#define WASM_ENABLE_BULK_MEMORY      1  /* bulk memory operations */
#define WASM_ENABLE_SHARED_MEMORY    1  /* shared memory (for threading) */
#define WASM_ENABLE_MULTI_MODULE     1  /* multiple module support */
#define WASM_ENABLE_TAIL_CALL        1  /* tail call optimization */
#define WASM_ENABLE_SIMD             1  /* SIMD instructions */
#define WASM_ENABLE_REF_TYPES        1  /* reference types */
#define WASM_ENABLE_CUSTOM_NAME_SECTION 1  /* debug names */
#define WASM_ENABLE_DUMP_CALL_STACK  1  /* stack traces on error */

/*
 * Debug/profiling (disabled in release)
 */
#ifdef NDEBUG
#define WASM_ENABLE_MEMORY_PROFILING 0
#define WASM_ENABLE_MEMORY_TRACING   0
#define WASM_ENABLE_PERF_PROFILING   0
#else
#define WASM_ENABLE_MEMORY_PROFILING 1
#define WASM_ENABLE_MEMORY_TRACING   0
#define WASM_ENABLE_PERF_PROFILING   1
#endif

/*
 * Platform layer
 * Use our custom Cosmopolitan platform implementation
 */
#define BUILD_PLATFORM_COSMOPOLITAN 1

/*
 * Thread support
 * Cosmopolitan supports pthreads on all platforms
 */
#define WASM_ENABLE_THREAD_MGR  1
#define WASM_ENABLE_LIB_PTHREAD 1

/*
 * Hardware bounds checking
 * Use guard pages where available for faster bounds checks
 */
#define WASM_ENABLE_HARDWARE_BOUNDARY_CHECK 1

#endif /* WAMR_CONFIG_H */
