/*
 * E9Patch Chrome Extension Content Script
 *
 * Injects into pages to enable WASM debugging support
 */

(function() {
  'use strict';

  // Track loaded WASM modules
  const wasmModules = new Map();

  // Intercept WebAssembly.instantiate
  const originalInstantiate = WebAssembly.instantiate;
  WebAssembly.instantiate = async function(source, importObject) {
    const result = await originalInstantiate.call(this, source, importObject);

    // Notify background about WASM module
    const module = result.module || result;
    const instance = result.instance || result;

    const moduleId = 'wasm_' + Date.now();
    wasmModules.set(moduleId, { module, instance });

    window.postMessage({
      type: 'E9PATCH_WASM_LOADED',
      moduleId,
      exports: Object.keys(instance.exports)
    }, '*');

    return result;
  };

  // Intercept WebAssembly.instantiateStreaming
  const originalInstantiateStreaming = WebAssembly.instantiateStreaming;
  if (originalInstantiateStreaming) {
    WebAssembly.instantiateStreaming = async function(source, importObject) {
      const result = await originalInstantiateStreaming.call(this, source, importObject);

      const moduleId = 'wasm_' + Date.now();
      wasmModules.set(moduleId, {
        module: result.module,
        instance: result.instance
      });

      window.postMessage({
        type: 'E9PATCH_WASM_LOADED',
        moduleId,
        exports: Object.keys(result.instance.exports)
      }, '*');

      return result;
    };
  }

  // Listen for messages from the extension
  window.addEventListener('message', (event) => {
    if (event.source !== window) return;
    if (!event.data || event.data.type !== 'E9PATCH_REQUEST') return;

    const { action, moduleId, params } = event.data;

    switch (action) {
      case 'getMemory':
        const entry = wasmModules.get(moduleId);
        if (entry && entry.instance.exports.memory) {
          const memory = entry.instance.exports.memory;
          const view = new Uint8Array(memory.buffer, params.offset, params.length);
          window.postMessage({
            type: 'E9PATCH_RESPONSE',
            action: 'memory',
            data: Array.from(view)
          }, '*');
        }
        break;

      case 'callFunction':
        const mod = wasmModules.get(moduleId);
        if (mod && mod.instance.exports[params.name]) {
          try {
            const result = mod.instance.exports[params.name](...params.args);
            window.postMessage({
              type: 'E9PATCH_RESPONSE',
              action: 'callResult',
              result
            }, '*');
          } catch (err) {
            window.postMessage({
              type: 'E9PATCH_RESPONSE',
              action: 'callError',
              error: err.message
            }, '*');
          }
        }
        break;

      case 'listModules':
        const modules = [];
        for (const [id, entry] of wasmModules) {
          modules.push({
            id,
            exports: Object.keys(entry.instance.exports)
          });
        }
        window.postMessage({
          type: 'E9PATCH_RESPONSE',
          action: 'moduleList',
          modules
        }, '*');
        break;
    }
  });

  console.log('E9Patch content script loaded');
})();
