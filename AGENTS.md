# E9Studio - Agent Context

> Shared context for contributors and LLM coding assistants (Claude Code, Copilot, Cursor, Aider, Continue, ...)

## Read First

| Priority | Source | What to Read | Why |
|----------|--------|--------------|-----|
| **1** | [jart/cosmopolitan](https://github.com/jart/cosmopolitan) | README, `tool/cosmocc/README.md`, `ape/` | The APE build uses cosmocc |
| **2** | [jart/cosmopolitan/libc/nt](https://github.com/jart/cosmopolitan/tree/master/libc/nt) | headers you call into | Windows APIs are declared there - never hand-declare them |
| **3** | [ludoplex/binaryen](https://github.com/ludoplex/binaryen) | README | WASM IR for object diffing |
| **4** | `FUNCTION_MANIFEST.md` and the `FUNCTION_SUBMANIFEST.md` of the directory you touch | function index | Reuse before you add |

**You need to understand:**
- APE polyglot structure (PE sections are ground truth, NOT ELF)
- cosmocc toolchain (pinned in `tool/cosmocc.mk`: cosmocc 4.0.2, GCC 14.1.0 by default, Clang 19 via `-mclang`)
- Run-time OS dispatch: cosmocc does not define `__linux__`, `__APPLE__` or `_WIN32`
- ZipOS virtual filesystem (`/zip/` paths)

**Getting these wrong results in:**
- Wrong APE patching (modifying ELF instead of PE sections)
- Dead code in the APE (an `#ifdef __linux__` branch is never compiled in)
- Broken Windows calls (hand-written prototypes truncate 64-bit HANDLEs and use the wrong calling convention)

---

## Overview

Binary patching tool for APE (Actually Portable Executable) polyglot binaries.
Its specs are dogfooded against [cosmo-bde](https://github.com/ludoplex/cosmo-bde),
a spec-driven C code generation framework.

## Critical Constraints

| Constraint | Rationale |
|------------|-----------|
| Pure C only (new code) | Dogfooding with C generators |
| APE-native | Patch ELF+PE+shell+ZipOS consistently |
| Spec-driven | Types from `.schema`, FSMs from `.sm` |
| Portable build | cosmocc produces one binary for every supported OS |

## Build and Test

```sh
make -f Makefile.e9studio toolchain   # once: fetch + sha256-verify cosmocc 4.0.2
make -f Makefile.e9studio all         # build/e9studio.com
make -f Makefile.e9studio check       # unit tests, --self-test, vendor tests
```

Use `COSMOCC=/path/to/cosmocc-4.0.2` to reuse an unpacked toolchain.

## Tool Compatibility

| Tool | Status | Notes |
|------|--------|-------|
| **cosmocc** | Required | Pinned version and sha256 in `tool/cosmocc.mk` |
| **Clang (cosmocc)** | OK | `cosmocc -mclang` |
| **Binaryen** | OK | Use ludoplex/binaryen (.com + .wasm outputs) |
| **TinyCC (libtcc)** | Not supported | Do not add it as a dependency |
| **libclang (library)** | Avoid | `libclang` (AST library) is not `clang` (compiler) |

**IR patching approaches (ordered by preference):**

| Approach | Ring | Notes |
|----------|------|-------|
| Ring 0 AST (Lemon+lexgen) | 0 | Pure C, fully dogfooded |
| Binaryen WASM (ludoplex) | 1 | .wasm in ZipOS |
| ccache (warm) | 1 | Requires cache hits |

See [docs/IR_PATCHING.md](docs/IR_PATCHING.md) for the Ring 0 composable architecture.

## File Map

```
specs/
├── e9ape.schema          # Type definitions (schemagen)
├── e9ape.sm              # State machines (smgen)
├── e9livereload.schema   # Live reload protocol
├── domain/               # Domain specs (c11_ast.schema, etc.)
├── parsing/              # Parser specs (c11.lex, c11.grammar)
├── behavior/             # State machines (livereload.sm, patch.sm)
└── features/             # BDD Gherkin specs

gen/
└── domain/               # Generated types (DO NOT HAND-EDIT)

src/e9patch/
├── e9ape.c,h             # APE patching (PE-based) - PURE C
├── e9livereload.c,h      # Live reload integration - PURE C
├── e9procmem.c,h         # Cross-platform process memory - PURE C
├── wasm/                 # Binaryen WASM integration
├── *.cpp                 # Legacy C++ (upstream e9patch)
└── vendor/               # Third-party code

test/unit/                # testlib-style unit tests (make check)
tool/                     # cosmocc pin + fetch script
```

**Note:** Legacy `.cpp` files exist but new code MUST be pure C.

## Naming

```
e9_{module}_{action}()   # Functions
e9_{name}_t              # Types
E9_{TYPE}_{VALUE}        # Enums
```

## Workflow

1. Search `FUNCTION_MANIFEST.md` / the directory's `FUNCTION_SUBMANIFEST.md` for an existing function.
2. Edit specs (`*.schema`, `*.sm`, `*.feature`) when the change affects types or state machines.
3. Regenerate `gen/` with the cosmo-bde generators (schemagen/smgen live in cosmo-bde, not in this repository) and commit the result; never hand-edit `gen/`.
4. Update `src/`, add or extend a test in `test/unit/`, run `make -f Makefile.e9studio check`.
5. Regenerate the function manifests and make sure the drift gate is clean before committing.

## Quick Reference

- Return `0` on success, `-1` on error
- Use `e9_livereload_get_error()` for error strings
- PE sections are ground truth for APE (no x86-64 ELF!)
- ZipOS contains embedded assets (e.g., `/zip/.cosmo/VERSION`, `binaryen.wasm`)
- OS-specific behaviour: `if (IsWindows()) ...` at run time, not `#ifdef _WIN32`

## Live Reload (Hot Patching)

Real-time C source → APE binary updates:

```
stat() poll → compiler (posix_spawnp, no shell) → Binaryen Diff → APE Patch → ICache Flush
```

Key files:
- `src/e9patch/e9livereload.h` - Live reload API
- `src/e9patch/e9livereload.c` - Integration layer
- `src/e9patch/e9ape.h` - APE patching (PE-based)
- `src/e9patch/wasm/e9binaryen.h` - Object diff via Binaryen
- `specs/e9livereload.schema` - Protocol spec

## Architecture Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) - Component architecture and data flow
- [doc/ape-anatomy-analysis.md](doc/ape-anatomy-analysis.md) - APE binary RE notes
- [doc/cosmopolitan-port.md](doc/cosmopolitan-port.md) - Portable build, toolchain pin, OS dispatch rules

## State Machines

- `specs/behavior/livereload.sm` - Live reload session lifecycle
- `specs/behavior/patch.sm` - Individual patch lifecycle

```
LiveReload States:
  UNINIT -> IDLE -> WATCHING -> COMPILING -> DIFFING -> PATCHING -> WATCHING

Patch States:
  PENDING -> APPLYING -> VERIFYING -> APPLIED <-> REVERTED
                                  \-> FAILED
```

## See Also

- [CONVENTIONS.md](CONVENTIONS.md) - Full style guide
- [LLM_CONTEXT.md](LLM_CONTEXT.md) - Where contributor context lives
- [specs/E9APE_DOGFOODING.md](specs/E9APE_DOGFOODING.md) - Dogfooding details
