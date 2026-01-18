# E9Patch Cosmopolitan Port

This document describes the Cosmopolitan Libc port of e9patch, enabling:
- **Portable executables** that run on Linux, macOS, Windows, and BSD
- **WebAssembly support** for browser-based binary rewriting
- **IDE integration** for live code updates from CLion

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                         CLion IDE                                │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │   C Source Editor  →  File Watcher  →  Change Detection  │   │
│  └──────────────────────────────────────────────────────────┘   │
│                              │ WebSocket                         │
└──────────────────────────────┼───────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────┐
│                    E9Patch (Cosmopolitan APE)                    │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐     │
│  │ Platform       │  │ IDE Bridge     │  │ e9patch Core   │     │
│  │ Abstraction    │◄─┤ (WebSocket +   │◄─┤ (Binary        │     │
│  │ Layer          │  │  inotify)      │  │  Rewriting)    │     │
│  └────────────────┘  └────────────────┘  └────────────────┘     │
└──────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────┐
│                       Chrome Browser                             │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐     │
│  │ e9patch.wasm   │◄─┤ JavaScript     │◄─┤ Web UI         │     │
│  │ (wasm3)        │  │ Bridge         │  │ (Debugging)    │     │
│  └────────────────┘  └────────────────┘  └────────────────┘     │
└──────────────────────────────────────────────────────────────────┘
```

## Key Components

### Platform Abstraction Layer (PAL)
- `src/e9patch/platform/e9platform.h` - Common interfaces
- `src/e9patch/platform/e9platform_native.cpp` - POSIX/Cosmopolitan implementation
- `src/e9patch/platform/e9platform_wasm.cpp` - WebAssembly implementation

### Cosmopolitan Integration
- `src/e9patch/platform/e9cosmo.h` - Cosmopolitan-specific APIs
- `src/e9patch/platform/e9cosmo.cpp` - hermit + wasm3 integration

### IDE Integration
- `src/e9patch/ide/clion_bridge.h` - C API for IDE communication
- `src/e9patch/ide/clion_bridge.cpp` - WebSocket server + file watcher

### Browser Interface
- `src/e9patch/web/e9patch_chrome.js` - JavaScript API for Chrome
- `src/e9patch/web/index.html` - Web UI for testing

## Building

### Prerequisites

1. **Cosmopolitan Libc**:
   ```bash
   git clone https://github.com/jart/cosmopolitan /opt/cosmo
   cd /opt/cosmo && make
   ```

2. **For WASM builds** (optional):
   ```bash
   # Install Emscripten
   git clone https://github.com/emscripten-core/emsdk.git
   cd emsdk && ./emsdk install latest && ./emsdk activate latest
   source emsdk_env.sh
   ```

### Build Commands

```bash
# Build APE (Actually Portable Executable)
make -f Makefile.cosmo all

# Build optimized release
make -f Makefile.cosmo release

# Build WASM module for browser
make -f Makefile.cosmo wasm

# Build with embedded wasm3 interpreter
make -f Makefile.cosmo wasm3-host

# Clean build artifacts
make -f Makefile.cosmo clean
```

### Build Outputs

| Target | Output | Description |
|--------|--------|-------------|
| `all` | `build/cosmo/e9patch.com` | APE binary (runs everywhere) |
| `wasm` | `build/cosmo/e9patch.wasm` | WASM module + JS bridge |
| `wasm3-host` | `build/cosmo/e9patch-wasm3.com` | APE with embedded wasm3 |

## Usage

### Command Line (APE Binary)

```bash
# Run on any OS - Linux, macOS, Windows, BSD
./e9patch.com --help

# Start with IDE integration
./e9patch.com --ide-port=9229

# Standard e9patch usage
./e9patch.com < input.json > output.bin
```

### Browser (WASM)

```javascript
// Initialize E9Patch
await E9Patch.init({ wasmUrl: './e9patch.wasm' });

// Load binary
await E9Patch.loadBinaryFromUrl('./my_program', 'my_program');

// Connect to CLion IDE
await E9Patch.IDE.connect('ws://localhost:9229');

// Set callbacks
E9Patch.callbacks.onPatchApplied = (addr, data) => {
    console.log(`Patched 0x${addr.toString(16)}`);
};

// Changes from IDE are automatically applied
// Download result
E9Patch.downloadPatchedBinary();
```

### CLion Integration

1. **Start e9patch with IDE mode**:
   ```bash
   ./e9patch.com --ide-port=9229
   ```

2. **Open Chrome debugging UI**:
   Open `http://localhost:8080` (or serve `src/e9patch/web/index.html`)

3. **Connect from CLion**:
   - Install WebSocket plugin or use terminal
   - Connect to `ws://localhost:9229`

4. **Edit source code**:
   - Modify C source files in CLion
   - Changes are detected via file watcher
   - Patches are applied automatically

## API Reference

### C API

```c
// Initialize Cosmopolitan mode
void e9cosmo_init(void);

// Load binary for patching
int e9cosmo_load_binary(const uint8_t *data, size_t size, const char *name);

// Apply patch at address
int e9cosmo_apply_patch(intptr_t address, const uint8_t *data, size_t size);

// Get patched binary
int e9cosmo_get_patched_binary(uint8_t **outData, size_t *outSize);

// Source change notification (from IDE)
int e9cosmo_on_source_change(const char *file, uint32_t lineStart,
                              uint32_t lineEnd, const char *content,
                              size_t contentLen);

// Breakpoint management
int e9cosmo_set_breakpoint(intptr_t address);
int e9cosmo_clear_breakpoint(intptr_t address);

// Hot reload
int e9cosmo_hot_reload(const char *sourceFile);
```

### JavaScript API

```javascript
// Core operations
await E9Patch.init(config);
await E9Patch.loadBinary(uint8Array, name);
await E9Patch.loadBinaryFromUrl(url, name);
E9Patch.getPatchedBinary();
E9Patch.downloadPatchedBinary(filename);

// IDE integration
await E9Patch.IDE.connect(wsUrl);
E9Patch.IDE.disconnect();

// Callbacks
E9Patch.callbacks.onPatchApplied = (addr, data) => {};
E9Patch.callbacks.onProgress = (current, total, msg) => {};
E9Patch.callbacks.onError = (code, msg) => {};
E9Patch.callbacks.onComplete = (success, path) => {};
E9Patch.callbacks.onSourceChange = (data) => {};

// Debugging
E9Patch.setBreakpoint(address);
E9Patch.clearBreakpoint(address);
E9Patch.hotReload(sourceFile);
```

## Integration with jart/cosmopolitan

This port leverages key Cosmopolitan features:

### hermit
- Syscall emulation for portable execution
- Works on Linux, macOS, Windows, BSD without modification
- No runtime dependencies

### wasm3
- Embedded WebAssembly interpreter
- Allows running WASM modules within the APE binary
- Bridge between native and web environments

### APE (Actually Portable Executable)
- Single binary that runs everywhere
- Self-modifying header adapts to host OS
- Polyglot binary format (ELF + PE + Mach-O + shell script)

## Dynamic Hot-Reload Workflow

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   CLion     │     │  e9patch    │     │   Chrome    │
│   IDE       │     │  (APE)      │     │   Browser   │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │
       │ Edit source.c     │                   │
       │───────────────────>                   │
       │                   │                   │
       │    File change    │                   │
       │    detected       │                   │
       │                   │                   │
       │    Recompile      │                   │
       │    source.c       │                   │
       │                   │                   │
       │    Generate       │                   │
       │    patches        │                   │
       │                   │                   │
       │                   │ Patch applied     │
       │                   │──────────────────>│
       │                   │                   │
       │                   │                   │ Update UI
       │                   │                   │
       │<──────────────────│<──────────────────│
       │   Status update   │   Status update   │
       │                   │                   │
```

## Limitations

1. **Tactic B0** (SIGILL-based patching) is not available in WASM mode
2. **fork/exec** not available in browser - single-threaded operation
3. **Direct memory mapping** not available in WASM - uses linear memory
4. **File system access** requires virtual filesystem in browser

## Future Enhancements

- [ ] Full Chrome DevTools Protocol integration
- [ ] Source-level debugging with DWARF
- [ ] Incremental compilation in browser
- [ ] Multi-binary support
- [ ] Remote debugging over network

## License

GPLv3+ - Same as e9patch
