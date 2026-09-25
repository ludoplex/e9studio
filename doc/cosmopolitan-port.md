# E9Studio Portable Build (Cosmopolitan Libc)

E9Studio is built with the `cosmocc` toolchain so that **one output file,
`build/e9studio.com`, runs unmodified on Linux, macOS, Windows, FreeBSD,
OpenBSD and NetBSD, on x86-64 and AArch64**. That portability is the reason
the project uses Cosmopolitan Libc: there is no per-OS build, installer or
runtime dependency to maintain.

## Toolchain

The toolchain version and its sha256 are pinned in
[`tool/cosmocc.mk`](../tool/cosmocc.mk) (cosmocc 4.0.2, the
`cosmocc-4.0.2.zip` release asset of
<https://github.com/jart/cosmopolitan/releases/tag/4.0.2>).

```sh
make -f Makefile.e9studio toolchain            # download, verify sha256, unpack to .cosmocc/4.0.2
make -f Makefile.e9studio COSMOCC=/path/to/cosmocc-4.0.2 all   # or reuse an unpacked copy
```

`tool/fetch-cosmocc.sh` refuses to unpack an archive whose sha256 does not
match, and never overwrites a directory it did not create.

## Build and test

```sh
make -f Makefile.e9studio all      # build/e9studio.com (APE, with ZipOS payload)
make -f Makefile.e9studio gui      # build/e9studio-gui.com
make -f Makefile.e9studio check    # unit tests (test/unit), --self-test, vendor tests
make -f Makefile.e9studio native   # host-compiler build for quick iteration (not an APE)
make -f Makefile.cosmo wasm        # browser build of the patching core (Emscripten)
```

`Makefile.cosmo` is kept as a compatibility entry point; its APE targets
forward to `Makefile.e9studio`. It no longer uses the retired
`cosmopolitan.h` amalgamation.

The upstream C++ rewriter (`e9patch`, `e9tool`) is **not** built as an APE:
its loaders are raw x86-64 Linux ELF/PE blobs and it relies on Linux-only
interfaces. Build it natively with the upstream `Makefile` / `build.sh`.

## Which Cosmopolitan facilities the code uses

| Need | Facility | Where |
|---|---|---|
| One binary for every OS | `cosmocc` -> APE | `Makefile.e9studio` |
| Pick OS behaviour at run time | `IsLinux()`, `IsWindows()`, `IsXnu()`, `IsBsd()` (`libc/dce.h`) | `e9procmem.c`, `e9studio.c`, `e9studio_gui.c` |
| Windows process memory | `OpenProcess`, `NtReadVirtualMemory`, `WriteProcessMemory`, `VirtualProtectEx` from `libc/nt/*.h` (64-bit handles, `ms_abi`) | `e9procmem.c` |
| Assets inside the executable | ZipOS: read via `/zip/...`, appended with `zipcopy` | `e9wasm_host.c`, `Makefile.e9studio` |
| Crash diagnostics | `ShowCrashReports()` | `main()` of `e9studio.c`, `e9studio_gui_main.c` |
| Path of the running program | `GetProgramExecutableName()` | `e9ape.c` |

Rules that follow from this (see `CONVENTIONS.md`):

- `cosmocc` does not define `__linux__`, `__APPLE__` or `_WIN32`. Code that
  must behave differently per OS dispatches at run time; `#ifdef` on those
  macros is only for native (non-APE) builds.
- Never hand-declare an OS API. Include the Cosmopolitan header that declares
  it, so types (64-bit `HANDLE`s) and calling conventions are right.
- Prefer a facility the toolchain already ships over vendoring or rewriting one.

## Process memory backends (`src/e9patch/e9procmem.c`)

| Host | Backend | Notes |
|---|---|---|
| Linux | `pread`/`pwrite` on `/proc/PID/mem` | no stop required; writes are forced through page protections |
| Windows | NT process handle | `OpenProcess` + `NtReadVirtualMemory` / `WriteProcessMemory` |
| macOS, BSD | self only | remote access reports `PROCMEM_ERR_PLATFORM` |

Self-patching makes the touched pages RWX; hosts that enforce W^X (Apple
silicon, OpenBSD) refuse that and the call reports `PROCMEM_ERR_PERM`.

## Live reload

The watcher polls `stat()` of `*.c` / `*.h` in the source directory (same code
on every OS) and spawns the compiler with `posix_spawnp` and an argv vector,
so file names are never interpreted by a shell.

## Browser build (WASM)

`make -f Makefile.cosmo wasm` compiles a subset of the C++ core with
Emscripten into `build/wasm/e9patch.js` (+ `.wasm`), driven by
`src/e9patch/web/e9patch_chrome.js`. This path does not use cosmocc. The
WebAssembly runtime embedded in `e9studio.com` is WAMR
(`src/e9patch/vendor/wamr`, with a Cosmopolitan platform layer).

## Known limitations

1. The CLion bridge (`src/e9patch/ide/clion_bridge.cpp`) uses inotify and is
   not part of the APE build.
2. Self-patching a running `e9studio.com` on Windows fails to open the image
   for writing (the loader holds it); patch a copy instead.
3. Remote process memory on macOS/BSD is not implemented.

## License

GPLv3+ - same as e9patch.
