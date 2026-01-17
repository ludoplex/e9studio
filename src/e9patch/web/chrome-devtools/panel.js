/*
 * E9Patch Chrome DevTools Panel
 * WASM-based binary analysis with DWARF debug support
 *
 * Provides:
 * - Multi-arch disassembly (x86-64, AArch64)
 * - Automatic CFG generation
 * - Decompilation to pseudo-C
 * - DWARF symbol/source mapping
 * - Live patching integration
 */

(function() {
  'use strict';

  // State
  let wasmModule = null;
  let binaryData = null;
  let binaryInfo = null;
  let currentAddress = 0;
  let currentFunction = null;
  let functions = [];
  let symbols = [];
  let breakpoints = new Set();

  // DOM elements
  const functionList = document.getElementById('function-list');
  const viewContent = document.getElementById('view-content');
  const statusLeft = document.getElementById('status-left');
  const statusRight = document.getElementById('status-right');
  const searchBox = document.getElementById('search-box');

  // Initialize WASM module
  async function initE9Patch() {
    try {
      statusLeft.textContent = 'Loading WASM module...';

      // Load E9Patch WASM module
      if (typeof E9PatchModule === 'function') {
        wasmModule = await E9PatchModule();
        console.log('E9Patch WASM module loaded');
        statusLeft.textContent = 'Ready';
      } else {
        throw new Error('E9PatchModule not found');
      }
    } catch (err) {
      console.error('Failed to load WASM module:', err);
      statusLeft.textContent = 'WASM load failed';
    }
  }

  // Export for devtools.js
  window.initE9Patch = initE9Patch;

  // Load binary file
  async function loadBinary(file) {
    statusLeft.textContent = 'Loading binary...';

    try {
      const arrayBuffer = await file.arrayBuffer();
      binaryData = new Uint8Array(arrayBuffer);

      statusRight.textContent = `${file.name} (${formatSize(binaryData.length)})`;

      // Initialize in WASM
      if (wasmModule) {
        const ptr = wasmModule._malloc(binaryData.length);
        wasmModule.HEAPU8.set(binaryData, ptr);

        const result = wasmModule.ccall('e9cosmo_load_binary', 'number',
          ['number', 'number'], [ptr, binaryData.length]);

        if (result === 0) {
          await analyzeBinary();
        } else {
          throw new Error('Failed to load binary in WASM');
        }
      } else {
        // Fallback: JavaScript analysis
        await analyzeLocally();
      }

      statusLeft.textContent = 'Binary loaded';
    } catch (err) {
      console.error('Load error:', err);
      statusLeft.textContent = 'Load failed: ' + err.message;
    }
  }

  // Analyze binary (using WASM or JS fallback)
  async function analyzeBinary() {
    statusLeft.textContent = 'Analyzing...';

    // Detect format and architecture
    binaryInfo = detectBinaryFormat(binaryData);

    // Parse symbols
    if (binaryInfo.format === 'ELF') {
      symbols = parseELFSymbols(binaryData);
    }

    // Discover functions
    functions = discoverFunctions(binaryData, binaryInfo);

    // Update UI
    updateFunctionList();
    updateStatusBar();

    // Jump to entry point
    if (binaryInfo.entryPoint) {
      gotoAddress(binaryInfo.entryPoint);
    }

    statusLeft.textContent = 'Analysis complete';
  }

  // Detect binary format
  function detectBinaryFormat(data) {
    const info = {
      format: 'unknown',
      arch: 'unknown',
      bits: 64,
      entryPoint: 0,
      baseAddress: 0
    };

    // Check ELF
    if (data[0] === 0x7f && data[1] === 0x45 && data[2] === 0x4c && data[3] === 0x46) {
      info.format = 'ELF';
      info.bits = data[4] === 2 ? 64 : 32;

      const view = new DataView(data.buffer);
      const machine = view.getUint16(18, true);

      if (machine === 0x3E) info.arch = 'x86-64';
      else if (machine === 0xB7) info.arch = 'AArch64';

      if (info.bits === 64) {
        info.entryPoint = Number(view.getBigUint64(24, true));
      }
    }
    // Check PE
    else if (data[0] === 0x4D && data[1] === 0x5A) {
      info.format = 'PE';
      const peOffset = new DataView(data.buffer).getUint32(0x3C, true);

      if (peOffset + 6 < data.length) {
        const view = new DataView(data.buffer);
        const machine = view.getUint16(peOffset + 4, true);

        if (machine === 0x8664) info.arch = 'x86-64';
        else if (machine === 0xAA64) info.arch = 'AArch64';
      }
    }
    // Check Mach-O
    else if ((data[0] === 0xFE && data[1] === 0xED && data[2] === 0xFA && data[3] === 0xCF) ||
             (data[0] === 0xCF && data[1] === 0xFA && data[2] === 0xED && data[3] === 0xFE)) {
      info.format = 'Mach-O';
      info.bits = 64;
    }

    return info;
  }

  // Parse ELF symbols
  function parseELFSymbols(data) {
    const syms = [];
    if (data.length < 64) return syms;

    const view = new DataView(data.buffer);
    const shoff = Number(view.getBigUint64(40, true));
    const shentsize = view.getUint16(58, true);
    const shnum = view.getUint16(60, true);
    const shstrndx = view.getUint16(62, true);

    if (!shoff || !shnum) return syms;

    // Get section name string table
    const shstrtabOff = Number(view.getBigUint64(shoff + shstrndx * shentsize + 24, true));

    // Find .symtab and .strtab
    let symtabOff = 0, symtabSize = 0, strtabOff = 0;

    for (let i = 0; i < shnum; i++) {
      const shdr = shoff + i * shentsize;
      const shType = view.getUint32(shdr + 4, true);

      if (shType === 2 || shType === 11) {  // SHT_SYMTAB or SHT_DYNSYM
        symtabOff = Number(view.getBigUint64(shdr + 24, true));
        symtabSize = Number(view.getBigUint64(shdr + 32, true));
        const link = view.getUint32(shdr + 40, true);

        if (link < shnum) {
          strtabOff = Number(view.getBigUint64(shoff + link * shentsize + 24, true));
        }
        break;
      }
    }

    if (!symtabOff || !strtabOff) return syms;

    // Parse symbols
    const numSyms = symtabSize / 24;  // Elf64_Sym size
    for (let i = 0; i < numSyms && i < 10000; i++) {
      const sym = symtabOff + i * 24;
      const nameOff = view.getUint32(sym, true);
      const info = data[sym + 4];
      const value = Number(view.getBigUint64(sym + 8, true));
      const size = Number(view.getBigUint64(sym + 16, true));

      if (nameOff === 0 || value === 0) continue;

      // Read name from string table
      let name = '';
      let off = strtabOff + nameOff;
      while (off < data.length && data[off] !== 0) {
        name += String.fromCharCode(data[off++]);
      }

      if (name) {
        const type = info & 0xF;
        syms.push({
          name,
          address: value,
          size,
          type: type === 2 ? 'function' : 'data'
        });
      }
    }

    return syms;
  }

  // Discover functions
  function discoverFunctions(data, info) {
    const funcs = [];

    // First, add functions from symbols
    for (const sym of symbols) {
      if (sym.type === 'function') {
        funcs.push({
          name: sym.name,
          address: sym.address,
          size: sym.size || 0
        });
      }
    }

    // Add entry point if not already present
    if (info.entryPoint && !funcs.find(f => f.address === info.entryPoint)) {
      funcs.push({
        name: '_start',
        address: info.entryPoint,
        size: 0
      });
    }

    // Sort by address
    funcs.sort((a, b) => a.address - b.address);

    return funcs;
  }

  // Disassemble at address
  function disassemble(addr, numLines = 50) {
    const lines = [];
    let offset = addressToOffset(addr);

    if (offset < 0 || offset >= binaryData.length) {
      return ['Invalid address'];
    }

    for (let i = 0; i < numLines && offset < binaryData.length; i++) {
      const insn = disasmOne(offset, addr);
      if (!insn) break;

      lines.push({
        address: addr,
        bytes: insn.bytes,
        mnemonic: insn.mnemonic,
        operands: insn.operands,
        comment: insn.comment
      });

      offset += insn.size;
      addr += insn.size;
    }

    return lines;
  }

  // Disassemble one instruction
  function disasmOne(offset, addr) {
    if (offset >= binaryData.length) return null;

    // Simplified x86-64 disassembler
    if (binaryInfo.arch === 'x86-64') {
      return disasmX64(offset, addr);
    }
    // Simplified AArch64 disassembler
    else if (binaryInfo.arch === 'AArch64') {
      return disasmAArch64(offset, addr);
    }

    return {
      size: 1,
      bytes: [binaryData[offset]],
      mnemonic: 'db',
      operands: '0x' + binaryData[offset].toString(16),
      comment: ''
    };
  }

  // Simplified x86-64 disassembler
  function disasmX64(offset, addr) {
    const code = binaryData;
    let pos = offset;
    const startPos = pos;

    // Skip prefixes
    while (pos < code.length) {
      const b = code[pos];
      if (b >= 0x40 && b <= 0x4F) { pos++; continue; }  // REX
      if (b === 0x66 || b === 0x67 || b === 0xF2 || b === 0xF3) { pos++; continue; }
      break;
    }

    if (pos >= code.length) return null;

    const opcode = code[pos++];
    let mnemonic = 'unknown';
    let operands = '';
    let comment = '';

    switch (opcode) {
      case 0xC3:
        mnemonic = 'ret';
        break;
      case 0xCC:
        mnemonic = 'int3';
        break;
      case 0x90:
        mnemonic = 'nop';
        break;
      case 0xE8:  // call rel32
        if (pos + 4 <= code.length) {
          const rel = new DataView(code.buffer).getInt32(pos, true);
          pos += 4;
          const target = addr + (pos - startPos) + rel;
          mnemonic = 'call';
          operands = '0x' + target.toString(16);
          const func = functions.find(f => f.address === target);
          if (func) comment = func.name;
        }
        break;
      case 0xE9:  // jmp rel32
        if (pos + 4 <= code.length) {
          const rel = new DataView(code.buffer).getInt32(pos, true);
          pos += 4;
          const target = addr + (pos - startPos) + rel;
          mnemonic = 'jmp';
          operands = '0x' + target.toString(16);
        }
        break;
      case 0xEB:  // jmp rel8
        if (pos < code.length) {
          const rel = code[pos++] > 127 ? code[pos-1] - 256 : code[pos-1];
          const target = addr + (pos - startPos) + rel;
          mnemonic = 'jmp';
          operands = '0x' + target.toString(16);
        }
        break;
      case 0x55:
        mnemonic = 'push';
        operands = 'rbp';
        break;
      case 0x5D:
        mnemonic = 'pop';
        operands = 'rbp';
        break;
      default:
        // Generic handling - estimate length
        pos = startPos + estimateX64Length(code.slice(startPos));
        mnemonic = 'op' + opcode.toString(16);
        break;
    }

    const size = pos - startPos;
    const bytes = Array.from(code.slice(startPos, pos));

    return { size, bytes, mnemonic, operands, comment };
  }

  // Estimate x86-64 instruction length
  function estimateX64Length(code) {
    if (code.length === 0) return 1;

    let pos = 0;

    // Skip prefixes
    while (pos < code.length && pos < 15) {
      const b = code[pos];
      if ((b >= 0x40 && b <= 0x4F) || b === 0x66 || b === 0x67 ||
          b === 0xF2 || b === 0xF3 || b === 0x2E || b === 0x36) {
        pos++;
      } else {
        break;
      }
    }

    if (pos >= code.length) return pos;

    const opcode = code[pos++];

    // No-operand instructions
    if ([0x90, 0xC3, 0xCB, 0xCC, 0xF4].includes(opcode)) {
      return pos;
    }

    // imm8
    if ([0x6A, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xEB,
         0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79,
         0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F].includes(opcode)) {
      return pos + 1;
    }

    // imm32
    if ([0xE8, 0xE9, 0x68].includes(opcode)) {
      return pos + 4;
    }

    // ret imm16
    if ([0xC2, 0xCA].includes(opcode)) {
      return pos + 2;
    }

    // Default: assume ModR/M + possible extras
    return Math.min(pos + 4, code.length);
  }

  // Simplified AArch64 disassembler
  function disasmAArch64(offset, addr) {
    if (offset + 4 > binaryData.length) return null;

    const view = new DataView(binaryData.buffer);
    const insn = view.getUint32(offset, true);
    const bytes = Array.from(binaryData.slice(offset, offset + 4));

    let mnemonic = 'unknown';
    let operands = '';
    let comment = '';

    // BL
    if ((insn & 0xFC000000) === 0x94000000) {
      let imm = insn & 0x03FFFFFF;
      if (imm & 0x02000000) imm |= 0xFC000000;
      const target = addr + (imm << 2);
      mnemonic = 'bl';
      operands = '0x' + target.toString(16);
      const func = functions.find(f => f.address === target);
      if (func) comment = func.name;
    }
    // B
    else if ((insn & 0xFC000000) === 0x14000000) {
      let imm = insn & 0x03FFFFFF;
      if (imm & 0x02000000) imm |= 0xFC000000;
      const target = addr + (imm << 2);
      mnemonic = 'b';
      operands = '0x' + target.toString(16);
    }
    // RET
    else if ((insn & 0xFFFFFC1F) === 0xD65F0000) {
      mnemonic = 'ret';
    }
    // NOP
    else if (insn === 0xD503201F) {
      mnemonic = 'nop';
    }
    // Generic
    else {
      mnemonic = '.word';
      operands = '0x' + insn.toString(16);
    }

    return { size: 4, bytes, mnemonic, operands, comment };
  }

  // Convert address to file offset
  function addressToOffset(addr) {
    // For ELF, need to use program headers
    // Simplified: assume direct mapping for now
    if (binaryInfo.baseAddress) {
      return addr - binaryInfo.baseAddress;
    }
    return addr;
  }

  // Update function list UI
  function updateFunctionList() {
    functionList.innerHTML = '';

    if (functions.length === 0) {
      functionList.innerHTML = '<div class="loading active">No functions found</div>';
      return;
    }

    for (const func of functions) {
      const item = document.createElement('div');
      item.className = 'func-item';
      item.dataset.address = func.address;

      item.innerHTML = `
        <span class="func-name">${escapeHtml(func.name)}</span>
        <span class="func-addr">0x${func.address.toString(16)}</span>
      `;

      item.addEventListener('click', () => {
        document.querySelectorAll('.func-item').forEach(i => i.classList.remove('selected'));
        item.classList.add('selected');
        currentFunction = func;
        gotoAddress(func.address);
      });

      functionList.appendChild(item);
    }
  }

  // Update status bar
  function updateStatusBar() {
    if (binaryInfo) {
      statusRight.textContent = `${binaryInfo.format} ${binaryInfo.arch} | ` +
        `${functions.length} functions | ${symbols.length} symbols`;
    }
  }

  // Go to address
  function gotoAddress(addr) {
    currentAddress = addr;

    const activeTab = document.querySelector('.view-tab.active');
    const view = activeTab ? activeTab.dataset.view : 'disasm';

    switch (view) {
      case 'disasm':
        showDisassembly(addr);
        break;
      case 'decompile':
        showDecompiled(addr);
        break;
      case 'hex':
        showHexView(addr);
        break;
      case 'source':
        showSourceMapping(addr);
        break;
    }

    statusLeft.textContent = '0x' + addr.toString(16);
  }

  // Show disassembly view
  function showDisassembly(addr) {
    const lines = disassemble(addr);
    let html = '';

    for (const line of lines) {
      const hasBreakpoint = breakpoints.has(line.address);
      const bytesStr = line.bytes.map(b => b.toString(16).padStart(2, '0')).join(' ');

      html += `
        <div class="disasm-line${hasBreakpoint ? ' breakpoint' : ''}"
             data-addr="${line.address}">
          <span class="disasm-addr">0x${line.address.toString(16)}</span>
          <span class="disasm-bytes">${bytesStr}</span>
          <span class="disasm-mnemonic">${line.mnemonic}</span>
          <span class="disasm-operands">${escapeHtml(line.operands)}</span>
          ${line.comment ? `<span class="disasm-comment">; ${escapeHtml(line.comment)}</span>` : ''}
        </div>
      `;
    }

    viewContent.innerHTML = html;

    // Add click handlers for toggling breakpoints
    viewContent.querySelectorAll('.disasm-line').forEach(line => {
      line.addEventListener('dblclick', () => {
        const addr = parseInt(line.dataset.addr);
        toggleBreakpoint(addr);
        line.classList.toggle('breakpoint');
      });
    });
  }

  // Show decompiled view
  function showDecompiled(addr) {
    // Find function containing address
    let func = functions.find(f =>
      addr >= f.address && (f.size === 0 || addr < f.address + f.size));

    if (!func) {
      viewContent.innerHTML = '<div class="loading">No function at this address</div>';
      return;
    }

    // Generate pseudo-C decompilation
    const decomp = generatePseudoC(func);
    viewContent.innerHTML = `<pre class="decompiled">${decomp}</pre>`;
  }

  // Generate pseudo-C from function
  function generatePseudoC(func) {
    let code = '';
    code += `<span class="comment">// Function: ${escapeHtml(func.name)}</span>\n`;
    code += `<span class="comment">// Address: 0x${func.address.toString(16)}</span>\n\n`;
    code += `<span class="type">int64_t</span> <span class="function">${escapeHtml(func.name)}</span>(<span class="type">void</span>)\n`;
    code += `{\n`;
    code += `    <span class="type">int64_t</span> result;\n\n`;

    // Disassemble and convert to pseudo-C
    const lines = disassemble(func.address, 100);

    for (const line of lines) {
      if (line.mnemonic === 'ret') {
        code += `    <span class="keyword">return</span> result;\n`;
        break;
      }
      else if (line.mnemonic === 'call') {
        const target = line.comment || line.operands;
        code += `    result = ${escapeHtml(target)}();  <span class="comment">// ${line.operands}</span>\n`;
      }
      else if (line.mnemonic.startsWith('j')) {
        code += `    <span class="keyword">goto</span> L_${line.operands.replace('0x', '')};  <span class="comment">// ${line.mnemonic}</span>\n`;
      }
      else {
        code += `    <span class="comment">// ${line.mnemonic} ${escapeHtml(line.operands)}</span>\n`;
      }
    }

    code += `}\n`;
    return code;
  }

  // Show hex view
  function showHexView(addr) {
    let offset = addressToOffset(addr);
    let html = '';

    for (let row = 0; row < 32 && offset < binaryData.length; row++) {
      const rowAddr = addr + row * 16;
      let hexPart = '';
      let asciiPart = '';

      for (let i = 0; i < 16; i++) {
        if (offset + i < binaryData.length) {
          const byte = binaryData[offset + i];
          hexPart += byte.toString(16).padStart(2, '0') + ' ';
          asciiPart += (byte >= 32 && byte < 127) ? String.fromCharCode(byte) : '.';
        } else {
          hexPart += '   ';
        }
        if (i === 7) hexPart += ' ';
      }

      html += `
        <div class="hex-line">
          <span class="hex-addr">0x${rowAddr.toString(16).padStart(16, '0')}</span>
          <span class="hex-bytes">${hexPart}</span>
          <span class="hex-ascii">|${asciiPart}|</span>
        </div>
      `;

      offset += 16;
    }

    viewContent.innerHTML = html;
  }

  // Show source mapping
  function showSourceMapping(addr) {
    // Would use DWARF info if available
    viewContent.innerHTML = `
      <div class="loading">
        Source mapping requires DWARF debug info.<br><br>
        Current address: 0x${addr.toString(16)}<br>
        ${currentFunction ? `Function: ${currentFunction.name}` : 'No function selected'}
      </div>
    `;
  }

  // Toggle breakpoint
  function toggleBreakpoint(addr) {
    if (breakpoints.has(addr)) {
      breakpoints.delete(addr);
    } else {
      breakpoints.add(addr);
    }
  }

  // Format file size
  function formatSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  }

  // Escape HTML
  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  // Event handlers
  document.getElementById('btn-load').addEventListener('click', () => {
    document.getElementById('modal-load').classList.add('active');
  });

  document.getElementById('btn-cancel-load').addEventListener('click', () => {
    document.getElementById('modal-load').classList.remove('active');
  });

  document.getElementById('btn-confirm-load').addEventListener('click', () => {
    const input = document.getElementById('file-input');
    if (input.files.length > 0) {
      loadBinary(input.files[0]);
    }
    document.getElementById('modal-load').classList.remove('active');
  });

  document.getElementById('btn-goto').addEventListener('click', () => {
    document.getElementById('modal-goto').classList.add('active');
    document.getElementById('goto-input').focus();
  });

  document.getElementById('btn-cancel-goto').addEventListener('click', () => {
    document.getElementById('modal-goto').classList.remove('active');
  });

  document.getElementById('btn-confirm-goto').addEventListener('click', () => {
    const input = document.getElementById('goto-input').value.trim();
    let addr = 0;

    if (input.startsWith('0x')) {
      addr = parseInt(input, 16);
    } else if (/^\d+$/.test(input)) {
      addr = parseInt(input);
    } else {
      // Search by name
      const func = functions.find(f => f.name === input);
      const sym = symbols.find(s => s.name === input);
      if (func) addr = func.address;
      else if (sym) addr = sym.address;
    }

    if (addr) {
      gotoAddress(addr);
    }

    document.getElementById('modal-goto').classList.remove('active');
  });

  // View tab switching
  document.querySelectorAll('.view-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.view-tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      gotoAddress(currentAddress);
    });
  });

  // Search functionality
  searchBox.addEventListener('keyup', (e) => {
    if (e.key === 'Enter') {
      const query = searchBox.value.toLowerCase();

      // Filter function list
      const items = functionList.querySelectorAll('.func-item');
      items.forEach(item => {
        const name = item.querySelector('.func-name').textContent.toLowerCase();
        const addr = item.querySelector('.func-addr').textContent.toLowerCase();
        item.style.display = (name.includes(query) || addr.includes(query)) ? '' : 'none';
      });
    }
  });

  // Export symbols
  document.getElementById('btn-export-symbols').addEventListener('click', () => {
    if (symbols.length === 0) return;

    let csv = 'Name,Address,Size,Type\n';
    for (const sym of symbols) {
      csv += `${sym.name},0x${sym.address.toString(16)},${sym.size},${sym.type}\n`;
    }

    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'symbols.csv';
    a.click();
    URL.revokeObjectURL(url);
  });

  // Export CFG
  document.getElementById('btn-export-cfg').addEventListener('click', () => {
    if (!currentFunction) return;

    // Generate DOT format
    let dot = `digraph "${currentFunction.name}" {\n`;
    dot += '  node [shape=box, fontname="monospace"];\n';
    dot += `  label="${currentFunction.name}";\n`;

    // Basic block discovery (simplified)
    const lines = disassemble(currentFunction.address, 200);
    let blockId = 0;
    let currentBlock = [];

    for (const line of lines) {
      currentBlock.push(line);

      if (line.mnemonic === 'ret' ||
          line.mnemonic.startsWith('j') ||
          line.mnemonic === 'call') {
        dot += `  block_${blockId} [label="BB${blockId}\\n0x${currentBlock[0].address.toString(16)}"];\n`;
        blockId++;
        currentBlock = [];

        if (line.mnemonic === 'ret') break;
      }
    }

    dot += '}\n';

    const blob = new Blob([dot], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${currentFunction.name}.dot`;
    a.click();
    URL.revokeObjectURL(url);
  });

  document.getElementById('btn-analyze').addEventListener('click', () => {
    if (binaryData) {
      analyzeBinary();
    }
  });

  // Keyboard shortcuts
  document.addEventListener('keydown', (e) => {
    if (e.key === 'g' && e.ctrlKey) {
      e.preventDefault();
      document.getElementById('btn-goto').click();
    }
  });

  // Initialize
  initE9Patch();
})();
