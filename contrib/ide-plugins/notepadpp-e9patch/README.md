# E9Patch Notepad++ Plugin

Live binary patching integration for Notepad++ with hot-reload support.

## Installation Options

### Option 1: PythonScript (Recommended)

Easier to install and modify. Requires PythonScript plugin.

1. **Install PythonScript plugin**:
   - Open Notepad++
   - Go to `Plugins` → `Plugins Admin`
   - Search for "PythonScript"
   - Install and restart

2. **Copy plugin files**:
   ```
   %APPDATA%\Notepad++\plugins\Config\PythonScript\scripts\
   ├── e9patch.py
   └── startup.py  (add content from e9patch_startup.py)
   ```

3. **Usage**:
   - Run via `Plugins` → `PythonScript` → `Scripts` → `e9patch`
   - Or configure auto-start via startup.py

### Option 2: Native DLL

Compile the native plugin for better integration.

1. **Build the DLL**:
   ```cmd
   cd native
   cl /LD /EHsc /O2 e9patch_npp.cpp ws2_32.lib user32.lib /Fe:E9Patch.dll
   ```

   Or with MinGW:
   ```cmd
   g++ -shared -o E9Patch.dll e9patch_npp.cpp -lws2_32 -luser32 -static
   ```

2. **Install**:
   ```cmd
   mkdir "%PROGRAMFILES%\Notepad++\plugins\E9Patch"
   copy E9Patch.dll "%PROGRAMFILES%\Notepad++\plugins\E9Patch\"
   ```

3. **Restart Notepad++**

## Usage

1. **Start e9patch server**:
   ```bash
   e9patch.com --ide-port=9229
   ```

2. **Open a C/C++ file** in Notepad++

3. **Connect** via plugin menu

4. **Edit and save** - changes sent automatically

## Commands (PythonScript)

Access via `Plugins` → `PythonScript` → `Scripts` → `e9patch`:

| Command | Description |
|---------|-------------|
| Connect | Connect to server |
| Disconnect | Disconnect from server |
| Toggle Breakpoint | Toggle breakpoint at cursor |
| Clear All Breakpoints | Clear all breakpoints |
| Hot Reload | Force hot reload |
| Status | Show connection status |

## Commands (Native DLL)

Access via `Plugins` → `E9Patch`:

| Menu Item | Description |
|-----------|-------------|
| Connect | Connect to server |
| Disconnect | Disconnect from server |
| Toggle Breakpoint | Toggle breakpoint at cursor |
| Clear Breakpoints | Clear all breakpoints |
| Hot Reload | Force hot reload |
| Status | Show connection status |

## Configuration

### PythonScript

Edit configuration at the top of `e9patch.py`:

```python
CONFIG = {
    "server_host": "localhost",
    "server_port": 9229,
    "auto_connect": True,
    "auto_reload": True,
    "show_notifications": True,
    "file_extensions": [".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hxx"],
}
```

### Native DLL

Edit `g_host` and `g_port` in `e9patch_npp.cpp` and recompile.

## Visual Indicators

When using PythonScript version:
- **Red circle** in margin: Breakpoint
- **Green arrow** in margin: Patched line

## Troubleshooting

### PythonScript not found
Make sure you installed PythonScript from Plugins Admin and restarted Notepad++.

### Connection failed
1. Check e9patch server is running: `e9patch.com --ide-port=9229`
2. Check firewall settings
3. Verify host/port configuration

### Native DLL not loading
1. Make sure DLL is in correct location
2. Check Notepad++ is 64-bit if DLL is 64-bit (or 32/32)
3. Check Windows Event Viewer for errors

## Requirements

- Notepad++ 7.0 or later
- For PythonScript: PythonScript plugin
- For Native: Visual Studio or MinGW for compilation

## License

GPL-3.0
