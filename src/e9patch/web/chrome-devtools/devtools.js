/*
 * E9Patch Chrome DevTools Integration
 * Creates the E9Patch panel in Chrome DevTools
 */

chrome.devtools.panels.create(
  "E9Patch",
  "icons/icon16.png",
  "panel.html",
  function(panel) {
    console.log("E9Patch DevTools panel created");

    panel.onShown.addListener(function(window) {
      // Panel is shown, initialize WASM module
      if (window.initE9Patch) {
        window.initE9Patch();
      }
    });

    panel.onHidden.addListener(function() {
      // Panel hidden
    });
  }
);

// Listen for debugger events
chrome.devtools.network.onRequestFinished.addListener(function(request) {
  // Monitor for WASM module loads
  if (request.request.url.endsWith('.wasm')) {
    console.log("WASM module loaded:", request.request.url);
  }
});
