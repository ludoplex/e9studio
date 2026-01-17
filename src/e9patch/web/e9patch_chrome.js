/**
 * e9patch_chrome.js
 * Chrome/Browser integration for e9patch with CLion IDE support
 *
 * Provides:
 * - FileSystem API for binary loading/saving
 * - WebSocket communication with IDE
 * - Chrome DevTools Protocol integration
 * - Source file watching and change detection
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

(function(global) {
    'use strict';

    /**
     * E9Patch Chrome Integration Module
     */
    const E9Patch = {
        version: '1.0.0',
        initialized: false,
        wasmModule: null,
        wasmInstance: null,
        memory: null,

        // Configuration
        config: {
            wasmUrl: './e9patch.wasm',
            ideWebSocketUrl: null,
            enableDebugLogging: false,
            autoReload: true,
        },

        // State
        state: {
            loadedBinary: null,
            loadedBinaryName: null,
            patchQueue: [],
            breakpoints: new Map(),
            sourceWatchers: new Map(),
        },

        // Callbacks
        callbacks: {
            onPatchApplied: null,
            onProgress: null,
            onError: null,
            onComplete: null,
            onSourceChange: null,
            onBreakpointHit: null,
        },
    };

    /**
     * Virtual FileSystem for WASM
     */
    E9Patch.FileSystem = {
        files: new Map(),

        exists(path) {
            return this.files.has(path);
        },

        getSize(path) {
            const file = this.files.get(path);
            return file ? file.byteLength : 0;
        },

        read(path) {
            const file = this.files.get(path);
            return file ? new Uint8Array(file) : null;
        },

        write(path, data) {
            this.files.set(path, data.buffer.slice(0));
            return true;
        },

        delete(path) {
            return this.files.delete(path);
        },

        clear() {
            this.files.clear();
        },

        // Load file from URL
        async loadFromUrl(path, url) {
            try {
                const response = await fetch(url);
                if (!response.ok) throw new Error(`HTTP ${response.status}`);
                const buffer = await response.arrayBuffer();
                this.files.set(path, buffer);
                return true;
            } catch (e) {
                console.error(`Failed to load ${url}:`, e);
                return false;
            }
        },

        // Load file from File object (drag & drop, file input)
        async loadFromFile(path, file) {
            return new Promise((resolve, reject) => {
                const reader = new FileReader();
                reader.onload = () => {
                    this.files.set(path, reader.result);
                    resolve(true);
                };
                reader.onerror = () => reject(reader.error);
                reader.readAsArrayBuffer(file);
            });
        },

        // Download file as blob
        download(path, filename) {
            const data = this.files.get(path);
            if (!data) return false;

            const blob = new Blob([data], { type: 'application/octet-stream' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename || path.split('/').pop();
            a.click();
            URL.revokeObjectURL(url);
            return true;
        },
    };

    /**
     * IDE Communication via WebSocket
     */
    E9Patch.IDE = {
        ws: null,
        reconnectAttempts: 0,
        maxReconnectAttempts: 5,
        reconnectDelay: 1000,

        async connect(url) {
            E9Patch.config.ideWebSocketUrl = url;
            return new Promise((resolve, reject) => {
                try {
                    this.ws = new WebSocket(url);

                    this.ws.onopen = () => {
                        console.log('[E9Patch] Connected to IDE');
                        this.reconnectAttempts = 0;
                        this.sendMessage('hello', { version: E9Patch.version });
                        resolve(true);
                    };

                    this.ws.onclose = () => {
                        console.log('[E9Patch] Disconnected from IDE');
                        this.scheduleReconnect();
                    };

                    this.ws.onerror = (error) => {
                        console.error('[E9Patch] WebSocket error:', error);
                        reject(error);
                    };

                    this.ws.onmessage = (event) => {
                        this.handleMessage(JSON.parse(event.data));
                    };
                } catch (e) {
                    reject(e);
                }
            });
        },

        disconnect() {
            if (this.ws) {
                this.ws.close();
                this.ws = null;
            }
        },

        scheduleReconnect() {
            if (this.reconnectAttempts >= this.maxReconnectAttempts) {
                console.error('[E9Patch] Max reconnect attempts reached');
                return;
            }
            this.reconnectAttempts++;
            const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);
            setTimeout(() => {
                if (E9Patch.config.ideWebSocketUrl) {
                    this.connect(E9Patch.config.ideWebSocketUrl);
                }
            }, delay);
        },

        sendMessage(type, data) {
            if (this.ws && this.ws.readyState === WebSocket.OPEN) {
                this.ws.send(JSON.stringify({ type, data, timestamp: Date.now() }));
            }
        },

        handleMessage(msg) {
            switch (msg.type) {
                case 'sourceChange':
                    this.onSourceChange(msg.data);
                    break;
                case 'setBreakpoint':
                    this.onSetBreakpoint(msg.data);
                    break;
                case 'removeBreakpoint':
                    this.onRemoveBreakpoint(msg.data);
                    break;
                case 'requestReload':
                    this.onRequestReload(msg.data);
                    break;
                case 'loadBinary':
                    this.onLoadBinary(msg.data);
                    break;
                default:
                    console.log('[E9Patch] Unknown message type:', msg.type);
            }
        },

        onSourceChange(data) {
            console.log('[E9Patch] Source change:', data.file);
            if (E9Patch.callbacks.onSourceChange) {
                E9Patch.callbacks.onSourceChange(data);
            }
            if (E9Patch.config.autoReload && E9Patch.wasmInstance) {
                E9Patch.notifySourceChange(
                    data.file,
                    data.lineStart,
                    data.lineEnd,
                    data.content
                );
            }
        },

        onSetBreakpoint(data) {
            E9Patch.state.breakpoints.set(`${data.file}:${data.line}`, data);
            if (E9Patch.wasmInstance) {
                E9Patch.setBreakpoint(data.address);
            }
        },

        onRemoveBreakpoint(data) {
            E9Patch.state.breakpoints.delete(`${data.file}:${data.line}`);
            if (E9Patch.wasmInstance) {
                E9Patch.clearBreakpoint(data.address);
            }
        },

        onRequestReload(data) {
            if (E9Patch.wasmInstance) {
                E9Patch.hotReload(data.file);
            }
        },

        async onLoadBinary(data) {
            if (data.url) {
                await E9Patch.loadBinaryFromUrl(data.url, data.name);
            } else if (data.base64) {
                const binary = Uint8Array.from(atob(data.base64), c => c.charCodeAt(0));
                await E9Patch.loadBinary(binary, data.name);
            }
        },

        // Send patch result back to IDE
        sendPatchResult(result) {
            this.sendMessage('patchResult', result);
        },

        // Send breakpoint hit notification
        sendBreakpointHit(info) {
            this.sendMessage('breakpointHit', info);
        },
    };

    /**
     * Initialize E9Patch WASM module
     */
    E9Patch.init = async function(config = {}) {
        Object.assign(this.config, config);

        // Set up global callbacks for WASM
        window.e9patchFileSystem = this.FileSystem;
        window.e9patchCallbacks = {
            onPatchApplied: (addr, data) => {
                if (this.callbacks.onPatchApplied) {
                    this.callbacks.onPatchApplied(addr, data);
                }
                this.IDE.sendPatchResult({ address: addr, data: Array.from(data) });
            },
            onProgress: (current, total, msg) => {
                if (this.callbacks.onProgress) {
                    this.callbacks.onProgress(current, total, msg);
                }
            },
            onError: (code, msg) => {
                console.error(`[E9Patch] Error ${code}: ${msg}`);
                if (this.callbacks.onError) {
                    this.callbacks.onError(code, msg);
                }
            },
            onComplete: (success, path) => {
                if (this.callbacks.onComplete) {
                    this.callbacks.onComplete(success, path);
                }
            },
        };

        // Load WASM module
        try {
            const response = await fetch(this.config.wasmUrl);
            const wasmBytes = await response.arrayBuffer();
            const { instance, module } = await WebAssembly.instantiate(wasmBytes, {
                env: this.createImports(),
                wasi_snapshot_preview1: this.createWasiImports(),
            });

            this.wasmModule = module;
            this.wasmInstance = instance;
            this.memory = instance.exports.memory;

            // Initialize WASM module
            if (instance.exports.e9cosmo_init) {
                instance.exports.e9cosmo_init();
            }

            this.initialized = true;
            console.log('[E9Patch] Initialized successfully');

            // Connect to IDE if URL provided
            if (this.config.ideWebSocketUrl) {
                await this.IDE.connect(this.config.ideWebSocketUrl);
            }

            return true;
        } catch (e) {
            console.error('[E9Patch] Initialization failed:', e);
            throw e;
        }
    };

    /**
     * Create WASM import functions
     */
    E9Patch.createImports = function() {
        return {
            // Memory management
            memory: new WebAssembly.Memory({ initial: 256, maximum: 4096 }),

            // Logging
            e9_log: (level, msgPtr) => {
                const msg = this.readString(msgPtr);
                const levels = ['debug', 'info', 'warn', 'error'];
                console[levels[level] || 'log']('[E9Patch]', msg);
            },

            // Callbacks to JS
            e9_on_patch_applied: (addr, size, dataPtr) => {
                const data = new Uint8Array(this.memory.buffer, dataPtr, size);
                window.e9patchCallbacks.onPatchApplied(addr, data.slice());
            },

            e9_on_progress: (current, total, msgPtr) => {
                const msg = this.readString(msgPtr);
                window.e9patchCallbacks.onProgress(current, total, msg);
            },

            e9_on_error: (code, msgPtr) => {
                const msg = this.readString(msgPtr);
                window.e9patchCallbacks.onError(code, msg);
            },

            e9_on_complete: (success, pathPtr) => {
                const path = this.readString(pathPtr);
                window.e9patchCallbacks.onComplete(success !== 0, path);
            },
        };
    };

    /**
     * Create WASI import functions
     */
    E9Patch.createWasiImports = function() {
        return {
            fd_write: () => 0,
            fd_read: () => 0,
            fd_close: () => 0,
            fd_seek: () => 0,
            environ_sizes_get: () => 0,
            environ_get: () => 0,
            proc_exit: (code) => { throw new Error(`Process exited with code ${code}`); },
            random_get: (bufPtr, bufLen) => {
                const buf = new Uint8Array(this.memory.buffer, bufPtr, bufLen);
                crypto.getRandomValues(buf);
                return 0;
            },
            clock_time_get: (clockId, precision, resultPtr) => {
                const view = new DataView(this.memory.buffer);
                view.setBigUint64(resultPtr, BigInt(Date.now() * 1000000), true);
                return 0;
            },
        };
    };

    /**
     * Helper: Read null-terminated string from WASM memory
     */
    E9Patch.readString = function(ptr) {
        if (!this.memory) return '';
        const mem = new Uint8Array(this.memory.buffer);
        let end = ptr;
        while (mem[end] !== 0) end++;
        return new TextDecoder().decode(mem.slice(ptr, end));
    };

    /**
     * Helper: Write string to WASM memory
     */
    E9Patch.writeString = function(str, ptr) {
        const encoder = new TextEncoder();
        const encoded = encoder.encode(str + '\0');
        const mem = new Uint8Array(this.memory.buffer);
        mem.set(encoded, ptr);
        return encoded.length;
    };

    /**
     * Load binary for patching
     */
    E9Patch.loadBinary = async function(data, name) {
        if (!this.initialized) throw new Error('E9Patch not initialized');

        // Store in virtual filesystem
        this.FileSystem.write(`/tmp/${name}`, data);

        // Call WASM function
        const exports = this.wasmInstance.exports;
        if (exports.e9cosmo_load_binary) {
            // Allocate memory and copy data
            const ptr = exports.malloc(data.byteLength);
            const mem = new Uint8Array(this.memory.buffer);
            mem.set(data, ptr);

            // Allocate and write name
            const namePtr = exports.malloc(name.length + 1);
            this.writeString(name, namePtr);

            const result = exports.e9cosmo_load_binary(ptr, data.byteLength, namePtr);

            exports.free(ptr);
            exports.free(namePtr);

            this.state.loadedBinary = data;
            this.state.loadedBinaryName = name;

            return result === 0;
        }
        return false;
    };

    /**
     * Load binary from URL
     */
    E9Patch.loadBinaryFromUrl = async function(url, name) {
        const response = await fetch(url);
        const data = new Uint8Array(await response.arrayBuffer());
        return this.loadBinary(data, name || url.split('/').pop());
    };

    /**
     * Notify source change from IDE
     */
    E9Patch.notifySourceChange = function(file, lineStart, lineEnd, content) {
        if (!this.initialized) return -1;

        const exports = this.wasmInstance.exports;
        if (exports.e9cosmo_on_source_change) {
            // Allocate strings
            const filePtr = exports.malloc(file.length + 1);
            this.writeString(file, filePtr);

            const contentPtr = exports.malloc(content.length + 1);
            this.writeString(content, contentPtr);

            const result = exports.e9cosmo_on_source_change(
                filePtr, lineStart, lineEnd, contentPtr, content.length
            );

            exports.free(filePtr);
            exports.free(contentPtr);

            return result;
        }
        return -1;
    };

    /**
     * Set breakpoint
     */
    E9Patch.setBreakpoint = function(address) {
        if (!this.initialized) return -1;
        const exports = this.wasmInstance.exports;
        if (exports.e9cosmo_set_breakpoint) {
            return exports.e9cosmo_set_breakpoint(address);
        }
        return -1;
    };

    /**
     * Clear breakpoint
     */
    E9Patch.clearBreakpoint = function(address) {
        if (!this.initialized) return -1;
        const exports = this.wasmInstance.exports;
        if (exports.e9cosmo_clear_breakpoint) {
            return exports.e9cosmo_clear_breakpoint(address);
        }
        return -1;
    };

    /**
     * Request hot reload
     */
    E9Patch.hotReload = function(sourceFile) {
        if (!this.initialized) return -1;
        const exports = this.wasmInstance.exports;
        if (exports.e9cosmo_hot_reload) {
            const filePtr = exports.malloc(sourceFile.length + 1);
            this.writeString(sourceFile, filePtr);
            const result = exports.e9cosmo_hot_reload(filePtr);
            exports.free(filePtr);
            return result;
        }
        return -1;
    };

    /**
     * Get patched binary
     */
    E9Patch.getPatchedBinary = function() {
        if (!this.initialized) return null;
        const exports = this.wasmInstance.exports;
        if (exports.e9cosmo_get_patched_binary) {
            // Allocate output pointers
            const dataPtr = exports.malloc(8);  // For uint8_t*
            const sizePtr = exports.malloc(8);  // For size_t

            const result = exports.e9cosmo_get_patched_binary(dataPtr, sizePtr);
            if (result !== 0) {
                exports.free(dataPtr);
                exports.free(sizePtr);
                return null;
            }

            const view = new DataView(this.memory.buffer);
            const actualDataPtr = view.getUint32(dataPtr, true);
            const actualSize = view.getUint32(sizePtr, true);

            const data = new Uint8Array(this.memory.buffer, actualDataPtr, actualSize).slice();

            exports.e9cosmo_free_patched_binary(actualDataPtr);
            exports.free(dataPtr);
            exports.free(sizePtr);

            return data;
        }
        return null;
    };

    /**
     * Download patched binary
     */
    E9Patch.downloadPatchedBinary = function(filename) {
        const data = this.getPatchedBinary();
        if (!data) return false;

        const blob = new Blob([data], { type: 'application/octet-stream' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename || `patched_${this.state.loadedBinaryName}`;
        a.click();
        URL.revokeObjectURL(url);
        return true;
    };

    // Export to global scope
    global.E9Patch = E9Patch;

})(typeof window !== 'undefined' ? window : global);

// Usage example:
// await E9Patch.init({ wasmUrl: './e9patch.wasm', ideWebSocketUrl: 'ws://localhost:9229' });
// await E9Patch.loadBinaryFromUrl('./my_program', 'my_program');
// E9Patch.callbacks.onPatchApplied = (addr, data) => console.log('Patched:', addr);
