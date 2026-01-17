# E9Patch Neovim Plugin

Live binary patching integration for Neovim with hot-reload support.

## Features

- **Auto-connect** to e9patch server on startup
- **Hot-reload** C/C++ changes on save
- **Breakpoint management** with sign column indicators
- **Statusline component** for connection status
- **Fully Lua-based** with no external dependencies (except `nc`)

## Installation

### lazy.nvim

```lua
{
    'e9patch/neovim-e9patch',
    ft = { 'c', 'cpp' },
    config = function()
        require('e9patch').setup({
            server_host = 'localhost',
            server_port = 9229,
            auto_connect = true,
            auto_reload = true,
        })
    end
}
```

### packer.nvim

```lua
use {
    'e9patch/neovim-e9patch',
    ft = { 'c', 'cpp' },
    config = function()
        require('e9patch').setup()
    end
}
```

### Manual

```bash
mkdir -p ~/.local/share/nvim/site/pack/e9patch/start/
cp -r contrib/ide-plugins/neovim-e9patch ~/.local/share/nvim/site/pack/e9patch/start/
```

Add to your `init.lua`:
```lua
require('e9patch').setup()
```

## Usage

1. **Start e9patch server**:
   ```bash
   ./e9patch.com --ide-port=9229
   ```

2. **Open a C/C++ file** in Neovim

3. **Check status** with `:E9Status` or statusline

4. **Edit and save** - changes are automatically sent to e9patch

## Commands

| Command | Description |
|---------|-------------|
| `:E9Connect` | Connect to server |
| `:E9Disconnect` | Disconnect from server |
| `:E9ToggleBreakpoint` | Toggle breakpoint at cursor |
| `:E9ClearBreakpoints` | Clear all breakpoints |
| `:E9HotReload` | Force hot reload |
| `:E9Status` | Show connection status |
| `:E9Browser` | Open browser debugger |

## Keybindings

| Key | Description |
|-----|-------------|
| `<leader>ec` | Connect |
| `<leader>ed` | Disconnect |
| `<leader>eb` | Toggle breakpoint |
| `<leader>er` | Hot reload |
| `<leader>es` | Show status |

## Configuration

```lua
require('e9patch').setup({
    server_host = 'localhost',      -- Server hostname
    server_port = 9229,             -- Server port
    auto_connect = true,            -- Auto-connect on startup
    auto_reload = true,             -- Auto-reload on save
    show_notifications = true,      -- Show vim.notify messages
    browser_url = 'http://localhost:8080',  -- Browser debugger URL
    signs = {
        breakpoint = { text = '●', hl = 'E9PatchBreakpoint' },
        patched = { text = '✓', hl = 'E9PatchPatched' },
    },
})
```

## Statusline Integration

### lualine.nvim

```lua
require('lualine').setup({
    sections = {
        lualine_x = {
            { require('e9patch').statusline }
        }
    }
})
```

### Manual

```lua
vim.o.statusline = vim.o.statusline .. ' %{g:e9patch_status}'
```

## Requirements

- Neovim >= 0.8
- `nc` (netcat) - usually pre-installed on Unix systems

## License

GPL-3.0
