---@mod e9patch E9Patch Neovim Plugin
---@brief [[
--- Live binary patching integration for Neovim with hot-reload support.
--- Connects to e9patch server via WebSocket for real-time code updates.
---
--- Installation with lazy.nvim:
--- >lua
---   {
---     'e9patch/neovim-e9patch',
---     ft = { 'c', 'cpp' },
---     config = function()
---       require('e9patch').setup()
---     end
---   }
--- <
---@brief ]]

local M = {}

-- Default configuration
M.config = {
    server_host = 'localhost',
    server_port = 9229,
    auto_connect = true,
    auto_reload = true,
    show_notifications = true,
    browser_url = 'http://localhost:8080',
    signs = {
        breakpoint = { text = '●', hl = 'E9PatchBreakpoint' },
        patched = { text = '✓', hl = 'E9PatchPatched' },
    },
}

-- State
local state = {
    connected = false,
    socket = nil,
    job_id = nil,
    breakpoints = {},  -- { [bufnr] = { [line] = true } }
    patches = {},      -- { [bufnr] = { { line = n, address = n } } }
    recv_buffer = '',
}

-- Namespace for signs and highlights
local ns_id = vim.api.nvim_create_namespace('e9patch')

---Setup highlights
local function setup_highlights()
    vim.api.nvim_set_hl(0, 'E9PatchBreakpoint', { fg = '#ef4444', bold = true })
    vim.api.nvim_set_hl(0, 'E9PatchPatched', { fg = '#4ade80', bold = true })
    vim.api.nvim_set_hl(0, 'E9PatchConnected', { fg = '#4ade80' })
    vim.api.nvim_set_hl(0, 'E9PatchDisconnected', { fg = '#a0a0a0' })
end

---Setup signs
local function setup_signs()
    vim.fn.sign_define('E9PatchBreakpoint', {
        text = M.config.signs.breakpoint.text,
        texthl = M.config.signs.breakpoint.hl,
    })
    vim.fn.sign_define('E9PatchPatched', {
        text = M.config.signs.patched.text,
        texthl = M.config.signs.patched.hl,
    })
end

---Log message
---@param msg string
---@param level? number
local function log(msg, level)
    level = level or vim.log.levels.INFO
    if M.config.show_notifications then
        vim.notify('[E9Patch] ' .. msg, level)
    end
end

---Update status line component
local function update_statusline()
    vim.g.e9patch_status = state.connected and 'E9:●' or 'E9:○'
end

---Send message to server
---@param msg table
local function send_message(msg)
    if not state.connected or not state.job_id then
        return false
    end

    msg.timestamp = os.time() * 1000
    local json = vim.json.encode(msg) .. '\n'

    -- For TCP socket via netcat job
    vim.fn.chansend(state.job_id, json)
    return true
end

---Handle incoming message
---@param data string
local function handle_message(data)
    local ok, msg = pcall(vim.json.decode, data)
    if not ok then
        return
    end

    if msg.type == 'patchResult' then
        local d = msg.data or msg
        if d.success then
            log(string.format('Patched at 0x%x', d.address or 0))

            -- Track patch
            if d.sourceFile and d.sourceLine then
                local bufnr = vim.fn.bufnr(d.sourceFile)
                if bufnr ~= -1 then
                    state.patches[bufnr] = state.patches[bufnr] or {}
                    table.insert(state.patches[bufnr], {
                        line = d.sourceLine,
                        address = d.address
                    })
                    M.update_signs(bufnr)
                end
            end
        else
            log('Patch failed: ' .. (d.error or 'unknown'), vim.log.levels.ERROR)
        end

    elseif msg.type == 'breakpointHit' then
        local d = msg.data or msg
        log(string.format('Breakpoint hit: %s:%d', d.sourceFile or '?', d.line or 0))

        -- Jump to location
        if d.sourceFile then
            vim.cmd('edit ' .. d.sourceFile)
            vim.api.nvim_win_set_cursor(0, { d.line or 1, 0 })
        end

    elseif msg.type == 'status' then
        log('Server ready')

    elseif msg.type == 'error' then
        log((msg.data and msg.data.message) or 'Unknown error', vim.log.levels.ERROR)
    end
end

---Process received data (handle partial messages)
---@param data string
local function process_recv(data)
    state.recv_buffer = state.recv_buffer .. data

    -- Process complete lines
    while true do
        local newline = state.recv_buffer:find('\n')
        if not newline then
            break
        end

        local line = state.recv_buffer:sub(1, newline - 1)
        state.recv_buffer = state.recv_buffer:sub(newline + 1)

        if #line > 0 then
            handle_message(line)
        end
    end
end

---Connect to e9patch server
function M.connect()
    if state.connected then
        log('Already connected')
        return
    end

    local host = M.config.server_host
    local port = M.config.server_port

    log(string.format('Connecting to %s:%d...', host, port))

    -- Use netcat for TCP connection (works on most systems)
    -- Alternative: use luasocket if available
    local cmd = { 'nc', host, tostring(port) }

    state.job_id = vim.fn.jobstart(cmd, {
        on_stdout = function(_, data, _)
            for _, line in ipairs(data) do
                if #line > 0 then
                    process_recv(line .. '\n')
                end
            end
        end,
        on_stderr = function(_, data, _)
            for _, line in ipairs(data) do
                if #line > 0 then
                    log('Error: ' .. line, vim.log.levels.ERROR)
                end
            end
        end,
        on_exit = function(_, code, _)
            state.connected = false
            state.job_id = nil
            update_statusline()
            log('Disconnected (exit code: ' .. code .. ')')

            -- Auto-reconnect
            if M.config.auto_connect then
                vim.defer_fn(function()
                    M.connect()
                end, 5000)
            end
        end,
    })

    if state.job_id > 0 then
        state.connected = true
        update_statusline()

        -- Send handshake
        vim.defer_fn(function()
            send_message({
                type = 'hello',
                data = {
                    client = 'neovim',
                    version = '1.0.0'
                }
            })
        end, 100)

        log('Connected')
    else
        log('Connection failed', vim.log.levels.ERROR)
    end
end

---Disconnect from server
function M.disconnect()
    if state.job_id then
        vim.fn.jobstop(state.job_id)
        state.job_id = nil
    end
    state.connected = false
    update_statusline()
    log('Disconnected')
end

---Send source change notification
---@param bufnr? number
function M.send_source_change(bufnr)
    bufnr = bufnr or vim.api.nvim_get_current_buf()

    if not state.connected then
        return
    end

    local filepath = vim.api.nvim_buf_get_name(bufnr)
    if filepath == '' then
        return
    end

    local lines = vim.api.nvim_buf_get_lines(bufnr, 0, -1, false)
    local content = table.concat(lines, '\n')

    send_message({
        type = 'sourceChange',
        data = {
            file = filepath,
            lineStart = 1,
            lineEnd = #lines,
            content = content
        }
    })
end

---Toggle breakpoint at current line
function M.toggle_breakpoint()
    local bufnr = vim.api.nvim_get_current_buf()
    local line = vim.api.nvim_win_get_cursor(0)[1]
    local filepath = vim.api.nvim_buf_get_name(bufnr)

    state.breakpoints[bufnr] = state.breakpoints[bufnr] or {}

    if state.breakpoints[bufnr][line] then
        -- Remove breakpoint
        state.breakpoints[bufnr][line] = nil
        send_message({
            type = 'removeBreakpoint',
            data = { file = filepath, line = line }
        })
        log(string.format('Removed breakpoint at line %d', line))
    else
        -- Add breakpoint
        state.breakpoints[bufnr][line] = true
        send_message({
            type = 'setBreakpoint',
            data = { file = filepath, line = line }
        })
        log(string.format('Set breakpoint at line %d', line))
    end

    M.update_signs(bufnr)
end

---Clear all breakpoints
function M.clear_breakpoints()
    state.breakpoints = {}

    send_message({
        type = 'clearAllBreakpoints',
        data = {}
    })

    -- Clear signs in all buffers
    for _, bufnr in ipairs(vim.api.nvim_list_bufs()) do
        vim.fn.sign_unplace('e9patch', { buffer = bufnr })
    end

    log('Cleared all breakpoints')
end

---Request hot reload
function M.hot_reload()
    local filepath = vim.api.nvim_buf_get_name(0)
    if filepath == '' then
        log('No file to reload', vim.log.levels.WARN)
        return
    end

    send_message({
        type = 'requestReload',
        data = { file = filepath }
    })

    log('Requested hot reload: ' .. vim.fn.fnamemodify(filepath, ':t'))
end

---Update signs for buffer
---@param bufnr number
function M.update_signs(bufnr)
    vim.fn.sign_unplace('e9patch', { buffer = bufnr })

    -- Add breakpoint signs
    local bp = state.breakpoints[bufnr]
    if bp then
        for line, _ in pairs(bp) do
            vim.fn.sign_place(0, 'e9patch', 'E9PatchBreakpoint', bufnr, { lnum = line })
        end
    end

    -- Add patch signs
    local patches = state.patches[bufnr]
    if patches then
        for _, patch in ipairs(patches) do
            vim.fn.sign_place(0, 'e9patch', 'E9PatchPatched', bufnr, { lnum = patch.line })
        end
    end
end

---Show status
function M.status()
    local lines = {
        'E9Patch Status',
        '==============',
        'Connected: ' .. (state.connected and 'Yes' or 'No'),
        string.format('Server: %s:%d', M.config.server_host, M.config.server_port),
        'Auto-connect: ' .. (M.config.auto_connect and 'Yes' or 'No'),
        'Auto-reload: ' .. (M.config.auto_reload and 'Yes' or 'No'),
    }

    -- Count breakpoints
    local bp_count = 0
    for _, bps in pairs(state.breakpoints) do
        for _, _ in pairs(bps) do
            bp_count = bp_count + 1
        end
    end
    table.insert(lines, 'Breakpoints: ' .. bp_count)

    vim.api.nvim_echo({{ table.concat(lines, '\n'), 'Normal' }}, true, {})
end

---Open browser debugger
function M.open_browser()
    local url = M.config.browser_url
    local cmd

    if vim.fn.has('mac') == 1 then
        cmd = { 'open', url }
    elseif vim.fn.has('unix') == 1 then
        cmd = { 'xdg-open', url }
    elseif vim.fn.has('win32') == 1 then
        cmd = { 'cmd', '/c', 'start', url }
    end

    if cmd then
        vim.fn.jobstart(cmd, { detach = true })
    end
end

---Get statusline component
---@return string
function M.statusline()
    if state.connected then
        return '%#E9PatchConnected#E9:●%*'
    else
        return '%#E9PatchDisconnected#E9:○%*'
    end
end

---Setup the plugin
---@param opts? table
function M.setup(opts)
    -- Merge config
    M.config = vim.tbl_deep_extend('force', M.config, opts or {})

    setup_highlights()
    setup_signs()
    update_statusline()

    -- Create user commands
    vim.api.nvim_create_user_command('E9Connect', M.connect, {})
    vim.api.nvim_create_user_command('E9Disconnect', M.disconnect, {})
    vim.api.nvim_create_user_command('E9ToggleBreakpoint', M.toggle_breakpoint, {})
    vim.api.nvim_create_user_command('E9ClearBreakpoints', M.clear_breakpoints, {})
    vim.api.nvim_create_user_command('E9HotReload', M.hot_reload, {})
    vim.api.nvim_create_user_command('E9Status', M.status, {})
    vim.api.nvim_create_user_command('E9Browser', M.open_browser, {})

    -- Setup keymaps
    vim.keymap.set('n', '<leader>ec', M.connect, { desc = 'E9Patch: Connect' })
    vim.keymap.set('n', '<leader>ed', M.disconnect, { desc = 'E9Patch: Disconnect' })
    vim.keymap.set('n', '<leader>eb', M.toggle_breakpoint, { desc = 'E9Patch: Toggle Breakpoint' })
    vim.keymap.set('n', '<leader>er', M.hot_reload, { desc = 'E9Patch: Hot Reload' })
    vim.keymap.set('n', '<leader>es', M.status, { desc = 'E9Patch: Status' })

    -- Auto-save handler
    local group = vim.api.nvim_create_augroup('E9Patch', { clear = true })

    vim.api.nvim_create_autocmd('BufWritePost', {
        group = group,
        pattern = { '*.c', '*.cpp', '*.cc', '*.cxx', '*.h', '*.hpp', '*.hxx' },
        callback = function(ev)
            if M.config.auto_reload then
                M.send_source_change(ev.buf)
            end
        end,
    })

    -- Update signs when entering buffer
    vim.api.nvim_create_autocmd('BufEnter', {
        group = group,
        pattern = { '*.c', '*.cpp', '*.cc', '*.cxx', '*.h', '*.hpp', '*.hxx' },
        callback = function(ev)
            M.update_signs(ev.buf)
        end,
    })

    -- Auto-connect
    if M.config.auto_connect then
        vim.defer_fn(function()
            M.connect()
        end, 100)
    end
end

return M
