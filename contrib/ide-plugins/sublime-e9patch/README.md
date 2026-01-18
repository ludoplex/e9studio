# E9Patch Sublime Text Plugin

Live binary patching integration for Sublime Text with hot-reload support.

## Features

- **Auto-connect** to e9patch server on startup
- **Hot-reload** C/C++ changes on save
- **Breakpoint management** with gutter icons
- **Status bar** with connection status
- **Pure Python** with no external dependencies

## Installation

### Package Control (Recommended)

Coming soon...

### Manual Installation

1. Open Sublime Text
2. Go to `Preferences` → `Browse Packages...`
3. Copy the `sublime-e9patch` folder to the Packages directory
4. Restart Sublime Text

Or via command line:

```bash
# macOS
cp -r contrib/ide-plugins/sublime-e9patch ~/Library/Application\ Support/Sublime\ Text/Packages/E9Patch

# Linux
cp -r contrib/ide-plugins/sublime-e9patch ~/.config/sublime-text/Packages/E9Patch

# Windows
xcopy contrib\ide-plugins\sublime-e9patch "%APPDATA%\Sublime Text\Packages\E9Patch" /E /I
```

## Usage

1. **Start e9patch server**:
   ```bash
   ./e9patch.com --ide-port=9229
   ```

2. **Open a C/C++ file** in Sublime Text

3. **Connect** via Command Palette: `E9Patch: Connect`

4. **Edit and save** - changes are automatically sent to e9patch

## Commands

Access via Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`):

| Command | Description |
|---------|-------------|
| `E9Patch: Connect` | Connect to server |
| `E9Patch: Disconnect` | Disconnect from server |
| `E9Patch: Toggle Breakpoint` | Toggle breakpoint at cursor |
| `E9Patch: Clear All Breakpoints` | Clear all breakpoints |
| `E9Patch: Hot Reload` | Force hot reload |
| `E9Patch: Show Status` | Show connection status |
| `E9Patch: Open Browser Debugger` | Open browser debugger |

## Keybindings

| Key | Command |
|-----|---------|
| `Ctrl+Shift+R` | Hot Reload |
| `Ctrl+Shift+B` | Toggle Breakpoint |

## Settings

Go to `Preferences` → `Package Settings` → `E9Patch` → `Settings`:

```json
{
    "server_host": "localhost",
    "server_port": 9229,
    "auto_connect": true,
    "auto_reload": true,
    "show_notifications": true,
    "browser_url": "http://localhost:8080",
    "file_patterns": [
        "*.c", "*.cpp", "*.cc", "*.cxx",
        "*.h", "*.hpp", "*.hxx"
    ]
}
```

## Visual Indicators

- **Red circle** in gutter: Breakpoint
- **Green highlight**: Patched line
- **Status bar**: Connection status

## Requirements

- Sublime Text 3 or 4
- Python 3.3+ (bundled with Sublime Text)

## License

GPL-3.0
