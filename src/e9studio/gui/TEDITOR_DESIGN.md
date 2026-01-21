# E9Studio GUI (cosmo-teditor)

## Overview

A portable GUI editor for E9Studio, inspired by the extensibility philosophy of teditor from MASM64 SDK. Built with Cosmopolitan Libc for cross-platform support (Windows, Linux, macOS, BSD).

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                      e9studio-gui.com                          │
│                 (Actually Portable Executable)                 │
├────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌──────────────────────┐   │
│  │   Editor    │  │  Analysis   │  │    Plugin System     │   │
│  │   (Text)    │  │   (Disasm)  │  │    (Extensions)      │   │
│  └──────┬──────┘  └──────┬──────┘  └──────────┬───────────┘   │
│         │                │                     │               │
│  ┌──────┴────────────────┴─────────────────────┴───────────┐  │
│  │                    Core Framework                        │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐ │  │
│  │  │  Window  │  │  Render  │  │  Events  │  │  Config  │ │  │
│  │  │  Manager │  │  Engine  │  │  System  │  │  Store   │ │  │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘ │  │
│  └──────────────────────────────────────────────────────────┘  │
├────────────────────────────────────────────────────────────────┤
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              Platform Abstraction Layer                   │  │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────────┐  │  │
│  │  │ Windows │  │  Linux  │  │  macOS  │  │ Framebuffer │  │  │
│  │  │   GUI   │  │   X11   │  │  Cocoa  │  │    (TUI)    │  │  │
│  │  └─────────┘  └─────────┘  └─────────┘  └─────────────┘  │  │
│  └──────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────┘
```

## Extensibility Philosophy

Following teditor's design principles:

1. **Simple Core**: Minimal base functionality
2. **Plugin Architecture**: Extensions add features
3. **Scripting Support**: Lua/WASM for user scripts
4. **Configuration Files**: INI/JSON for settings
5. **Modular UI**: Dockable panels, customizable layout

## Components

### 1. Core Framework

```c
// e9studio_gui.h
typedef struct E9Window E9Window;
typedef struct E9Panel E9Panel;
typedef struct E9Plugin E9Plugin;

// Window management
E9Window *e9gui_create_window(const char *title, int width, int height);
void e9gui_destroy_window(E9Window *win);
int e9gui_main_loop(E9Window *win);

// Panel system
E9Panel *e9gui_create_panel(E9Window *win, const char *id, int dock_position);
void e9gui_panel_set_content(E9Panel *panel, void *content, size_t size);

// Plugin system
int e9gui_register_plugin(E9Plugin *plugin);
int e9gui_load_plugin(const char *path);
```

### 2. Panel Types

| Panel | Description |
|-------|-------------|
| Editor | Text editing with syntax highlighting |
| Disasm | Disassembly view from e9analysis |
| Decompile | Decompiled C code view |
| Hex | Hex dump view |
| Console | Command output and logs |
| Projects | File tree browser |
| Symbols | Symbol table viewer |
| Functions | Function list |
| Xrefs | Cross-reference viewer |
| Scanner | Memory scanner (E9Scanner) |

### 3. Plugin Interface

```c
// e9studio_plugin.h
#define E9_PLUGIN_API_VERSION 1

typedef struct {
    int api_version;
    const char *name;
    const char *version;
    const char *author;

    int (*init)(void);
    void (*shutdown)(void);

    // UI hooks
    void (*on_menu_build)(E9Menu *menu);
    void (*on_panel_create)(E9Panel *panel);

    // Analysis hooks
    void (*on_binary_load)(E9Binary *bin);
    void (*on_function_analyze)(E9Function *func);

    // Editor hooks
    void (*on_text_change)(E9Editor *ed, int line, const char *text);
} E9PluginInfo;

#define E9_PLUGIN_EXPORT(info) \
    __attribute__((visibility("default"))) \
    E9PluginInfo *e9_plugin_info(void) { return &info; }
```

### 4. Platform Abstraction

```c
// e9gui_platform.h

// Detect platform at runtime (Cosmopolitan)
typedef enum {
    E9_PLATFORM_WINDOWS,
    E9_PLATFORM_LINUX,
    E9_PLATFORM_MACOS,
    E9_PLATFORM_BSD,
    E9_PLATFORM_UNKNOWN
} E9Platform;

E9Platform e9gui_get_platform(void);

// Graphics backend selection
typedef enum {
    E9_BACKEND_WIN32,      // Windows GDI/Direct2D
    E9_BACKEND_X11,        // Linux X11
    E9_BACKEND_COCOA,      // macOS Cocoa
    E9_BACKEND_FRAMEBUFFER,// Framebuffer (fallback)
    E9_BACKEND_TUI         // Terminal UI (no GUI)
} E9Backend;

E9Backend e9gui_select_backend(void);
```

## Build System

### Makefile Integration

```makefile
# In Makefile.e9studio
GUI_SRC = src/e9studio/gui/e9studio_gui.c \
          src/e9studio/gui/e9gui_window.c \
          src/e9studio/gui/e9gui_panel.c \
          src/e9studio/gui/e9gui_editor.c \
          src/e9studio/gui/e9gui_plugin.c \
          src/e9studio/gui/platform/e9gui_win32.c \
          src/e9studio/gui/platform/e9gui_x11.c \
          src/e9studio/gui/platform/e9gui_tui.c

# Build with cosmocc
e9studio-gui.com: $(GUI_SRC) $(ANALYSIS_LIB)
	$(COSMOCC) $(CFLAGS) -o $@ $^ -lm
```

## Command Line Interface

```bash
# Default: GUI mode
./e9studio-gui.com binary.elf

# Force TUI mode (fallback)
./e9studio-gui.com --tui binary.elf
./e9studio.com binary.elf  # Original TUI binary

# Headless mode (for scripting)
./e9studio-gui.com --headless --script analyze.lua binary.elf

# Plugin loading
./e9studio-gui.com --plugin scanner.so binary.elf
```

## Configuration

### e9studio.ini

```ini
[gui]
theme = dark
font = Consolas
font_size = 12
tab_size = 4

[layout]
panels = editor,disasm,console
editor_position = left
disasm_position = right
console_position = bottom

[plugins]
autoload = scanner,binaryen

[analysis]
auto_analyze = true
decompile_on_select = true
```

## Integration with Existing TUI

The existing `e9studio.com` TUI becomes the fallback when:
1. GUI backend unavailable (no display)
2. `--tui` flag specified
3. SSH/remote session detected
4. `E9STUDIO_TUI=1` environment variable set

```c
// In e9studio_gui.c main()
int main(int argc, char **argv) {
    // Check for TUI fallback conditions
    if (should_use_tui(argc, argv)) {
        return e9studio_tui_main(argc, argv);  // Existing TUI
    }

    // Initialize GUI
    E9Backend backend = e9gui_select_backend();
    if (backend == E9_BACKEND_TUI) {
        return e9studio_tui_main(argc, argv);
    }

    // Start GUI...
}
```

## Rendering Strategy

### Cross-Platform Rendering

1. **Windows**: Win32 GDI or Direct2D
2. **Linux**: X11 with Cairo or OpenGL
3. **macOS**: Cocoa with Core Graphics
4. **Fallback**: Software framebuffer → TUI

### Minimal Dependencies

Using Cosmopolitan's built-in graphics support where available:
- `__gui_start()` / `__gui_close()` for window management
- Direct framebuffer access for portable rendering
- Custom widget toolkit (no GTK/Qt dependency)

## Phase 1 Implementation

Initial MVP features:
1. Single window with editor panel
2. Basic text editing with syntax highlighting
3. Disassembly panel using e9analysis
4. Command console
5. File open/save dialogs
6. TUI fallback mode

## Future Phases

### Phase 2
- Full panel docking system
- Decompilation view
- Memory scanner integration
- Plugin loading

### Phase 3
- Scripting support (Lua/WASM)
- Debugger integration
- Remote debugging
- Collaboration features

## References

- MASM64 SDK teditor: Extensibility-focused assembly editor
- Cosmopolitan Libc: https://github.com/jart/cosmopolitan
- E9Patch: Binary rewriting engine
- ImGui: Inspiration for immediate-mode rendering
