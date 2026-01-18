/*
 * E9Patch Chrome Extension Background Service Worker
 *
 * Handles:
 * - Native messaging with e9studio
 * - WebSocket connection to IDE bridge
 * - Debugger integration
 */

const NATIVE_HOST = 'com.e9patch.studio';
const WS_PORT = 9229;

let wsConnection = null;
let nativePort = null;

// Connect to native host (e9studio)
function connectNative() {
  try {
    nativePort = chrome.runtime.connectNative(NATIVE_HOST);

    nativePort.onMessage.addListener((message) => {
      console.log('Native message:', message);
      handleNativeMessage(message);
    });

    nativePort.onDisconnect.addListener(() => {
      console.log('Native port disconnected');
      nativePort = null;
    });

    console.log('Connected to native host');
  } catch (err) {
    console.log('Native messaging not available:', err);
  }
}

// Connect to WebSocket (IDE bridge)
function connectWebSocket() {
  try {
    wsConnection = new WebSocket(`ws://localhost:${WS_PORT}`);

    wsConnection.onopen = () => {
      console.log('WebSocket connected');
    };

    wsConnection.onmessage = (event) => {
      try {
        const message = JSON.parse(event.data);
        handleIDEMessage(message);
      } catch (err) {
        console.error('WebSocket parse error:', err);
      }
    };

    wsConnection.onclose = () => {
      console.log('WebSocket closed, reconnecting...');
      wsConnection = null;
      setTimeout(connectWebSocket, 5000);
    };

    wsConnection.onerror = (err) => {
      console.log('WebSocket error:', err);
    };
  } catch (err) {
    console.log('WebSocket not available:', err);
  }
}

// Handle messages from native host
function handleNativeMessage(message) {
  switch (message.type) {
    case 'analysisComplete':
      // Notify DevTools panel
      chrome.runtime.sendMessage({
        type: 'analysisResult',
        data: message.data
      });
      break;

    case 'patchReady':
      chrome.runtime.sendMessage({
        type: 'patchAvailable',
        address: message.address,
        size: message.size
      });
      break;

    case 'error':
      chrome.runtime.sendMessage({
        type: 'error',
        message: message.message
      });
      break;
  }
}

// Handle messages from IDE
function handleIDEMessage(message) {
  switch (message.type) {
    case 'sourceChanged':
      // Source file changed in IDE
      if (nativePort) {
        nativePort.postMessage({
          type: 'compileAndDiff',
          path: message.path
        });
      }
      break;

    case 'breakpointSet':
      // IDE set a breakpoint
      chrome.runtime.sendMessage({
        type: 'breakpoint',
        action: 'set',
        file: message.file,
        line: message.line
      });
      break;

    case 'breakpointCleared':
      chrome.runtime.sendMessage({
        type: 'breakpoint',
        action: 'clear',
        file: message.file,
        line: message.line
      });
      break;
  }
}

// Message handler from DevTools panel
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  switch (request.type) {
    case 'loadBinary':
      if (nativePort) {
        nativePort.postMessage({
          type: 'loadBinary',
          path: request.path
        });
      }
      sendResponse({ success: true });
      break;

    case 'analyze':
      if (nativePort) {
        nativePort.postMessage({
          type: 'analyze',
          address: request.address
        });
      }
      sendResponse({ success: true });
      break;

    case 'applyPatch':
      if (nativePort) {
        nativePort.postMessage({
          type: 'applyPatch',
          patches: request.patches
        });
      }
      sendResponse({ success: true });
      break;

    case 'getStatus':
      sendResponse({
        native: nativePort !== null,
        websocket: wsConnection !== null && wsConnection.readyState === WebSocket.OPEN
      });
      break;
  }

  return true;  // Keep message channel open for async response
});

// Debugger integration
chrome.debugger.onEvent.addListener((source, method, params) => {
  if (method === 'Debugger.paused') {
    // Execution paused
    chrome.runtime.sendMessage({
      type: 'debuggerPaused',
      callFrames: params.callFrames,
      reason: params.reason
    });
  }
});

// Initialize connections
connectNative();
connectWebSocket();

console.log('E9Patch background service worker started');
