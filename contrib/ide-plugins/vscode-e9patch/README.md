# E9Patch VS Code Extension

Live binary patching integration for VS Code with hot-reload support.

## Features

- **Auto-connect** to e9patch server on startup
- **Hot-reload** C/C++ changes on save
- **Breakpoint management** with visual indicators
- **Patch visualization** showing applied patches
- **Status bar** with connection status

## Installation

### From VSIX

```bash
cd contrib/ide-plugins/vscode-e9patch
npm install
npm run package
code --install-extension e9patch-1.0.0.vsix
```

### Development Mode

```bash
cd contrib/ide-plugins/vscode-e9patch
npm install
npm run watch
# Press F5 in VS Code to launch Extension Development Host
```

## Usage

1. **Start e9patch server**:
   ```bash
   ./e9patch.com --ide-port=9229
   ```

2. **Open a C/C++ project** in VS Code

3. **Check status bar** - should show green checkmark when connected

4. **Edit and save** - changes are automatically sent to e9patch

## Commands

| Command | Keybinding | Description |
|---------|------------|-------------|
| E9Patch: Connect | - | Connect to server |
| E9Patch: Disconnect | - | Disconnect from server |
| E9Patch: Set Breakpoint | `Ctrl+Shift+B` | Toggle breakpoint at cursor |
| E9Patch: Force Hot Reload | `Ctrl+Shift+R` | Trigger immediate reload |
| E9Patch: Show Status | Click status bar | Show connection info |
| E9Patch: Open Browser | - | Open browser debugger |

## Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `e9patch.serverHost` | `localhost` | Server hostname |
| `e9patch.serverPort` | `9229` | Server port |
| `e9patch.autoConnect` | `true` | Auto-connect on startup |
| `e9patch.autoReload` | `true` | Auto-reload on save |
| `e9patch.showNotifications` | `true` | Show patch notifications |
| `e9patch.browserUrl` | `http://localhost:8080` | Browser debugger URL |

## Protocol

The extension communicates using JSON over WebSocket:

```json
// Send on file save
{"type": "sourceChange", "data": {"file": "/path/to/main.c", "content": "..."}}

// Receive patch result
{"type": "patchResult", "data": {"address": 4198400, "success": true}}
```

## License

GPL-3.0
