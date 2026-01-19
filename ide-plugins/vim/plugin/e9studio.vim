" E9Studio Vim Plugin
" Binary analysis and patching integration
"
" Commands:
"   :E9Open <file>        - Open binary for analysis
"   :E9Disasm [address]   - Show disassembly
"   :E9Decompile [address]- Show decompiled C
"   :E9Functions          - List functions
"   :E9Goto <address>     - Go to address
"   :E9Nop <address> <size> - NOP bytes
"   :E9Apply              - Apply patches
"   :E9Save [path]        - Save patched binary
"
" Requires: Vim 8+ or Neovim with job/channel support

if exists('g:loaded_e9studio')
    finish
endif
let g:loaded_e9studio = 1

" Configuration
let g:e9studio_executable = get(g:, 'e9studio_executable', 'e9studio.com')
let g:e9studio_show_bytes = get(g:, 'e9studio_show_bytes', 0)

" State
let s:job = v:null
let s:channel = v:null
let s:current_binary = ''
let s:request_id = 0
let s:pending_requests = {}

" JSON-RPC helpers
function! s:NextId()
    let s:request_id += 1
    return s:request_id
endfunction

function! s:SendRequest(method, params, callback)
    if s:channel == v:null
        echoerr 'E9Studio: Not connected'
        return
    endif

    let l:id = s:NextId()
    let l:request = json_encode({
        \ 'jsonrpc': '2.0',
        \ 'id': l:id,
        \ 'method': a:method,
        \ 'params': a:params
        \ })

    let s:pending_requests[l:id] = a:callback

    let l:header = 'Content-Length: ' . len(l:request) . "\r\n\r\n"

    if has('nvim')
        call chansend(s:channel, l:header . l:request)
    else
        call ch_sendraw(s:channel, l:header . l:request)
    endif
endfunction

function! s:HandleResponse(channel, msg)
    " Parse JSON-RPC response
    let l:start = stridx(a:msg, '{')
    if l:start == -1
        return
    endif

    try
        let l:response = json_decode(a:msg[l:start:])

        if has_key(l:response, 'id')
            let l:id = l:response.id
            if has_key(s:pending_requests, l:id)
                let l:callback = s:pending_requests[l:id]
                unlet s:pending_requests[l:id]

                if has_key(l:response, 'result')
                    call l:callback(l:response.result, v:null)
                elseif has_key(l:response, 'error')
                    call l:callback(v:null, l:response.error)
                endif
            endif
        endif
    catch
        " Ignore parse errors
    endtry
endfunction

" Start E9Studio process
function! s:Start()
    if s:job != v:null
        return
    endif

    if has('nvim')
        let s:job = jobstart([g:e9studio_executable, '--ide-mode'], {
            \ 'on_stdout': {ch, data, name -> s:HandleResponseNvim(data)},
            \ 'on_stderr': {ch, data, name -> s:HandleStderr(data)},
            \ 'on_exit': {ch, code, name -> s:HandleExit(code)}
            \ })
        let s:channel = s:job
    else
        let s:job = job_start([g:e9studio_executable, '--ide-mode'], {
            \ 'out_mode': 'raw',
            \ 'out_cb': function('s:HandleResponse'),
            \ 'err_cb': function('s:HandleStderr'),
            \ 'exit_cb': function('s:HandleExit')
            \ })
        let s:channel = job_getchannel(s:job)
    endif

    " Initialize
    call s:SendRequest('initialize', {'clientInfo': {'name': 'vim-e9studio'}},
        \ {result, err -> s:OnInitialized(result, err)})
endfunction

function! s:HandleResponseNvim(data)
    for l:line in a:data
        call s:HandleResponse(v:null, l:line)
    endfor
endfunction

function! s:HandleStderr(channel, msg)
    " Log stderr but don't display
endfunction

function! s:HandleExit(channel, code)
    let s:job = v:null
    let s:channel = v:null
    let s:current_binary = ''
endfunction

function! s:OnInitialized(result, err)
    if a:err != v:null
        echoerr 'E9Studio: Initialization failed: ' . string(a:err)
        return
    endif
    echo 'E9Studio: Connected'
endfunction

" Commands
function! E9Open(path)
    call s:Start()

    call s:SendRequest('binary/open', {'path': a:path},
        \ {result, err -> s:OnBinaryOpened(result, err, a:path)})
endfunction

function! s:OnBinaryOpened(result, err, path)
    if a:err != v:null
        echoerr 'E9Studio: Failed to open binary: ' . a:err.message
        return
    endif

    let s:current_binary = a:path
    echo printf('E9Studio: Opened %s %s binary (%d functions)',
        \ a:result.arch, a:result.format, a:result.numFunctions)
endfunction

function! E9Disasm(address)
    if s:current_binary == ''
        echoerr 'E9Studio: No binary open'
        return
    endif

    let l:addr = a:address
    if l:addr =~ '^0x'
        let l:addr = str2nr(l:addr, 16)
    else
        let l:addr = str2nr(l:addr)
    endif

    call s:SendRequest('analysis/getDisassembly',
        \ {'address': l:addr, 'count': 50},
        \ {result, err -> s:OnDisassembly(result, err)})
endfunction

function! s:OnDisassembly(result, err)
    if a:err != v:null
        echoerr 'E9Studio: Disassembly failed: ' . a:err.message
        return
    endif

    " Open scratch buffer
    new
    setlocal buftype=nofile
    setlocal bufhidden=wipe
    setlocal noswapfile
    setlocal filetype=asm
    file [E9Studio Disassembly]

    " Fill with disassembly
    let l:lines = []
    for l:insn in a:result.instructions
        call add(l:lines, printf('%s  %s', l:insn.address, l:insn.text))
    endfor
    call setline(1, l:lines)
endfunction

function! E9Decompile(address)
    if s:current_binary == ''
        echoerr 'E9Studio: No binary open'
        return
    endif

    let l:addr = a:address
    if l:addr =~ '^0x'
        let l:addr = str2nr(l:addr, 16)
    else
        let l:addr = str2nr(l:addr)
    endif

    call s:SendRequest('analysis/getDecompilation',
        \ {'address': l:addr},
        \ {result, err -> s:OnDecompilation(result, err)})
endfunction

function! s:OnDecompilation(result, err)
    if a:err != v:null
        echoerr 'E9Studio: Decompilation failed: ' . a:err.message
        return
    endif

    " Open scratch buffer
    new
    setlocal buftype=nofile
    setlocal bufhidden=wipe
    setlocal noswapfile
    setlocal filetype=c
    file [E9Studio Decompilation]

    call setline(1, split(a:result.code, "\n"))
endfunction

function! E9Functions()
    if s:current_binary == ''
        echoerr 'E9Studio: No binary open'
        return
    endif

    call s:SendRequest('analysis/getFunctions', {},
        \ {result, err -> s:OnFunctions(result, err)})
endfunction

function! s:OnFunctions(result, err)
    if a:err != v:null
        echoerr 'E9Studio: Failed to get functions: ' . a:err.message
        return
    endif

    " Use location list
    let l:items = []
    for l:func in a:result.functions
        let l:name = l:func.name != '' ? l:func.name : 'sub_' . l:func.address[2:]
        call add(l:items, {
            \ 'text': printf('%s  %s (%d bytes)', l:func.address, l:name, l:func.size),
            \ 'type': 'I'
            \ })
    endfor

    call setqflist(l:items)
    copen
endfunction

function! E9Nop(address, size)
    if s:current_binary == ''
        echoerr 'E9Studio: No binary open'
        return
    endif

    let l:addr = a:address
    if l:addr =~ '^0x'
        let l:addr = str2nr(l:addr, 16)
    else
        let l:addr = str2nr(l:addr)
    endif

    call s:SendRequest('patch/nop',
        \ {'address': l:addr, 'size': str2nr(a:size)},
        \ {result, err -> s:OnPatchCreated(result, err)})
endfunction

function! s:OnPatchCreated(result, err)
    if a:err != v:null
        echoerr 'E9Studio: Patch failed: ' . a:err.message
        return
    endif

    echo 'E9Studio: Created patch (id: ' . a:result.patchId . ')'
endfunction

function! E9Apply()
    call s:SendRequest('patch/apply', {},
        \ {result, err -> s:OnPatchApplied(result, err)})
endfunction

function! s:OnPatchApplied(result, err)
    if a:err != v:null
        echoerr 'E9Studio: Apply failed: ' . a:err.message
        return
    endif

    echo 'E9Studio: Patches applied'
endfunction

function! E9Save(...)
    let l:path = a:0 > 0 ? a:1 : s:current_binary . '.patched'

    call s:SendRequest('patch/save', {'path': l:path},
        \ {result, err -> s:OnSaved(result, err, l:path)})
endfunction

function! s:OnSaved(result, err, path)
    if a:err != v:null
        echoerr 'E9Studio: Save failed: ' . a:err.message
        return
    endif

    echo 'E9Studio: Saved to ' . a:path
endfunction

" Register commands
command! -nargs=1 -complete=file E9Open call E9Open(<q-args>)
command! -nargs=1 E9Disasm call E9Disasm(<q-args>)
command! -nargs=1 E9Decompile call E9Decompile(<q-args>)
command! E9Functions call E9Functions()
command! -nargs=1 E9Goto call E9Disasm(<q-args>)
command! -nargs=+ E9Nop call call('E9Nop', split(<q-args>))
command! E9Apply call E9Apply()
command! -nargs=? -complete=file E9Save call E9Save(<f-args>)
